#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define INITIAL_CAP 10

struct list {
    char pid[16];
    char name[256];
    char ppid[16];
    char uid[16];
    char cmdline[1024];
};

struct box {
    struct list *p;
    int cap;
    int count;
};

/* ---------- small helpers ---------- */

int is_num(char *name)
{
    int i = 0;
    while(name[i] != '\0')
    {
        if(isdigit((unsigned char)name[i]) == 0)
            return 0;
        i++;
    }
    return 1;
}

void print_json_str(const char *s)
{
    while(*s)
    {
        if(*s == '"')       printf("\\\"");
        else if(*s == '\\') printf("\\\\");
        else if(*s == '\n') printf("\\n");
        else if(*s == '\r') printf("\\r");
        else if(*s == '\t') printf("\\t");
        else                putchar(*s);
        s++;
    }
}

long now_seconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return (long)now.tv_sec;
}

/* ---------- box (dynamic array) management ---------- */

void box_init(struct box *b, int cap)
{
    b->cap = cap;
    b->count = 0;
    b->p = malloc(cap * sizeof(struct list));
}

/* Ensure there is room for at least one more entry, growing (doubling) if needed. */
int box_ensure_capacity(struct box *b)
{
    if(b->count < b->cap)
        return 1;

    int new_cap = b->cap * 2;
    struct list *temp = realloc(b->p, new_cap * sizeof(struct list));
    if(temp == NULL)
    {
        free(b->p);
        fprintf(stderr, "realloc failed\n");
        return 0;
    }
    b->p = temp;
    b->cap = new_cap;
    return 1;
}

/* Make sure dst can hold at least `needed` entries (used for the previous-scan snapshot). */
int box_ensure_min_capacity(struct box *b, int needed)
{
    if(needed <= b->cap)
        return 1;

    struct list *temp = realloc(b->p, needed * sizeof(struct list));
    if(temp == NULL)
    {
        free(b->p);
        fprintf(stderr, "realloc failed\n");
        return 0;
    }
    b->p = temp;
    b->cap = needed;
    return 1;
}

void box_free(struct box *b)
{
    free(b->p);
    b->p = NULL;
    b->cap = 0;
    b->count = 0;
}

/* ---------- reading /proc/<pid> data ---------- */

/* Fill in name/pid/ppid/uid from /proc/<pid>/status. Returns 1 on success, 0 if the
   status file couldn't be opened (process likely gone). */
int read_proc_status(const char *pid_str, struct list *entry)
{
    char path[512];
    snprintf(path, sizeof(path), "/proc/%s/status", pid_str);

    FILE *f = fopen(path, "r");
    if(f == NULL)
        return 0;

    int got_name = 0, got_ppid = 0, got_uid = 0;
    char line[256];

    while(fgets(line, sizeof(line), f))
    {
        if(strncmp(line, "Name:", 5) == 0)
        {
            sscanf(line, "Name: %255s", entry->name);
            strncpy(entry->pid, pid_str, sizeof(entry->pid) - 1);
            entry->pid[sizeof(entry->pid) - 1] = '\0';
            got_name = 1;
        }
        else if(strncmp(line, "PPid:", 5) == 0)
        {
            sscanf(line, "PPid: %15s", entry->ppid);
            got_ppid = 1;
        }
        else if(strncmp(line, "Uid:", 4) == 0)
        {
            sscanf(line, "Uid: %15s", entry->uid);
            got_uid = 1;
        }
        if(got_name && got_ppid && got_uid)
            break;
    }
    fclose(f);
    return 1;
}

/* Fill in cmdline from /proc/<pid>/cmdline, falling back to `name` if empty/unreadable. */
void read_proc_cmdline(const char *pid_str, struct list *entry)
{
    char cmd_path[512];
    snprintf(cmd_path, sizeof(cmd_path), "/proc/%s/cmdline", pid_str);

    FILE *cf = fopen(cmd_path, "r");
    if(cf == NULL)
        return;

    int len = fread(entry->cmdline, 1, sizeof(entry->cmdline) - 1, cf);
    fclose(cf);

    if(len > 0)
    {
        entry->cmdline[len] = '\0';
        /* cmdline args are NUL-separated; turn them into spaces for display,
           except for the trailing terminator. */
        for(int i = 0; i < len - 1; i++)
        {
            if(entry->cmdline[i] == '\0')
                entry->cmdline[i] = ' ';
        }
    }
    else
    {
        strncpy(entry->cmdline, entry->name, sizeof(entry->cmdline) - 1);
        entry->cmdline[sizeof(entry->cmdline) - 1] = '\0';
    }
}

/* ---------- scanning ---------- */

/* Scan /proc and populate `arr` with all currently running processes.
   Returns 0 on fatal error, 1 on success. */
int scan_processes(struct box *arr)
{
    box_init(arr, INITIAL_CAP);

    DIR *dir = opendir("/proc");
    if(dir == NULL)
    {
        printf("Couldn't open directory");
        return 0;
    }

    struct dirent *entry;
    while((entry = readdir(dir)) != NULL)
    {
        if(!is_num(entry->d_name))
            continue;

        if(!box_ensure_capacity(arr))
        {
            closedir(dir);
            return 0;
        }

        struct list *slot = &arr->p[arr->count];

        if(!read_proc_status(entry->d_name, slot))
            continue; /* process disappeared mid-scan */

        read_proc_cmdline(entry->d_name, slot);
        arr->count++;
    }

    closedir(dir);
    return 1;
}

/* ---------- diffing / event output ---------- */

int find_by_pid(struct box *b, const char *pid)
{
    for(int i = 0; i < b->count; i++)
    {
        if(strcmp(b->p[i].pid, pid) == 0)
            return i;
    }
    return -1;
}

void print_start_event(struct list *proc)
{
    long ts = now_seconds();
    printf("{\"event\":\"process_start\",\"pid\":%s,\"name\":\"", proc->pid);
    print_json_str(proc->name);
    printf("\",\"ppid\":%s,\"uid\":%s,\"cmdline\":\"", proc->ppid, proc->uid);
    print_json_str(proc->cmdline);
    printf("\",\"ts\":%ld}\n", ts);
}

void print_exit_event(struct list *proc)
{
    long ts = now_seconds();
    printf("{\"event\":\"process_exit\",\"pid\":%s,\"name\":\"", proc->pid);
    print_json_str(proc->name);
    printf("\",\"ppid\":%s,\"uid\":%s,\"ts\":%ld}\n", proc->ppid, proc->uid, ts);
}

/* Compare current scan (`arr`) against the previous scan (`p_arr`) and print
   process_start / process_exit events accordingly. */
void report_diff(struct box *arr, struct box *p_arr)
{
    for(int k = 0; k < arr->count; k++)
    {
        if(find_by_pid(p_arr, arr->p[k].pid) == -1)
            print_start_event(&arr->p[k]);
    }

    for(int k = 0; k < p_arr->count; k++)
    {
        if(find_by_pid(arr, p_arr->p[k].pid) == -1)
            print_exit_event(&p_arr->p[k]);
    }
}

/* Copy `src` (the latest scan) into `dst` (the snapshot kept for the next iteration). */
int save_snapshot(struct box *dst, struct box *src)
{
    if(!box_ensure_min_capacity(dst, src->count))
        return 0;

    for(int i = 0; i < src->count; i++)
        dst->p[i] = src->p[i]; /* plain struct copy: all fields are fixed-size arrays */

    dst->count = src->count;
    return 1;
}

/* ---------- main loop ---------- */

int main(void)
{
    struct timespec sleep_ts = { .tv_sec = 0, .tv_nsec = 500000000L };

    struct box p_arr;
    box_init(&p_arr, INITIAL_CAP);

    int first_scan = 1;

    while(1)
    {
        struct box arr;
        if(!scan_processes(&arr))
            return 1;

        if(!first_scan)
            report_diff(&arr, &p_arr);

        if(!save_snapshot(&p_arr, &arr))
        {
            box_free(&arr);
            return 1;
        }

        first_scan = 0;
        box_free(&arr);
        nanosleep(&sleep_ts, NULL);
    }

    return 0;
}