#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

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

void box_free(struct box *b)
{
    free(b->p);
    b->p = NULL;
    b->cap = 0;
    b->count = 0;
}

void box_remove_at(struct box *b, int idx)
{
    if(idx < 0 || idx >= b->count)
        return;
    b->p[idx] = b->p[b->count - 1];
    b->count--;
}

/* ---------- reading /proc/<pid> data ---------- */

int read_proc_status(const char *pid_str, struct list *entry)
{
    char path[512];
    snprintf(path, sizeof(path), "/proc/%s/status", pid_str);

    FILE *f = fopen(path, "r");
    if(f == NULL)
        return 0; /* process already gone - expected and fine, caller handles it */

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
    fflush(stdout);
}

void print_exit_event(struct list *proc)
{
    long ts = now_seconds();
    printf("{\"event\":\"process_exit\",\"pid\":%s,\"name\":\"", proc->pid);
    print_json_str(proc->name);
    printf("\",\"ppid\":%s,\"uid\":%s,\"ts\":%ld}\n", proc->ppid, proc->uid, ts);
    fflush(stdout);
}

/* ---------- NEW: one-time initial /proc scan ----------
 *
 * This is NOT polling - it runs exactly once, at startup, before the
 * netlink loop begins. Its only job is to seed `cache` with processes
 * that were already running before this agent started, so that if one
 * of them exits later, PROC_EVENT_EXIT can still find a cached
 * name/ppid/uid for it instead of printing nothing.
 *
 * It deliberately does NOT print process_start events for these -
 * they didn't just start, your agent just started watching. If you
 * want a "process already running at agent startup" event type,
 * that's a one-line addition in the loop below, kept separate on
 * purpose so "process_start" always means "actually just started."
 */
int seed_cache_from_proc(struct box *cache)
{
    DIR *dir = opendir("/proc");
    if(dir == NULL)
    {
        fprintf(stderr, "Couldn't open /proc for initial scan\n");
        return 0;
    }

    struct dirent *entry;
    while((entry = readdir(dir)) != NULL)
    {
        if(!is_num(entry->d_name))
            continue;

        if(!box_ensure_capacity(cache))
        {
            closedir(dir);
            return 0;
        }

        struct list *slot = &cache->p[cache->count];

        if(!read_proc_status(entry->d_name, slot))
            continue; /* gone before we got to it - fine, skip */

        read_proc_cmdline(entry->d_name, slot);
        cache->count++;
    }

    closedir(dir);
    return 1;
}

/* ---------- netlink PROC_EVENTS ---------- */

struct proc_subscribe_msg {
    struct nlmsghdr nl_hdr;
    struct __attribute__((__packed__)) {
        struct cn_msg cn_msg;
        enum proc_cn_mcast_op cn_mcast;
    };
} __attribute__((aligned(NLMSG_ALIGNTO)));

struct proc_event_msg {
    struct nlmsghdr nl_hdr;
    struct __attribute__((__packed__)) {
        struct cn_msg cn_msg;
        struct proc_event proc_ev;
    };
} __attribute__((aligned(NLMSG_ALIGNTO)));

int netlink_proc_open(void)
{
    int sock_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if(sock_fd == -1)
    {
        perror("socket");
        return -1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = CN_IDX_PROC;

    if(bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind");
        close(sock_fd);
        return -1;
    }

    struct proc_subscribe_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.nl_hdr.nlmsg_len = sizeof(msg);
    msg.nl_hdr.nlmsg_pid = getpid();
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;
    msg.cn_msg.id.idx = CN_IDX_PROC;
    msg.cn_msg.id.val = CN_VAL_PROC;
    msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);
    msg.cn_mcast = PROC_CN_MCAST_LISTEN;

    if(send(sock_fd, &msg, sizeof(msg), 0) == -1)
    {
        perror("send (subscribe)");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

/* ---------- main: netlink drives it, /proc only enriches ---------- */

int main(void)
{
    struct box cache;
    box_init(&cache, INITIAL_CAP);

    if(!seed_cache_from_proc(&cache))
    {
        box_free(&cache);
        return 1;
    }

    int sock_fd = netlink_proc_open();
    if(sock_fd == -1)
    {
        box_free(&cache);
        return 1;
    }

    printf("Subscribed. Waiting for kernel-pushed process events...\n");
    fflush(stdout);

    struct proc_event_msg msg;

    while(1)
    {
        ssize_t recv_len = recv(sock_fd, &msg, sizeof(msg), 0);
        if(recv_len == -1)
        {
            perror("recv");
            break;
        }
        if(recv_len == 0)
            break;

        struct proc_event *ev = &msg.proc_ev;

        if(ev->what == PROC_EVENT_EXEC)
        {
            pid_t pid = ev->event_data.exec.process_pid;
            char pid_str[16];
            snprintf(pid_str, sizeof(pid_str), "%d", pid);

            struct list fresh = {0};
            if(!read_proc_status(pid_str, &fresh))
            {
                continue;
            }
            read_proc_cmdline(pid_str, &fresh);

            /* Update-or-insert into the cache so a later EXIT can
             * find this pid's details.
             */
            int idx = find_by_pid(&cache, pid_str);
            if(idx >= 0)
            {
                cache.p[idx] = fresh;
            }
            else
            {
                if(!box_ensure_capacity(&cache))
                {
                    box_free(&cache);
                    close(sock_fd);
                    return 1;
                }
                cache.p[cache.count] = fresh;
                cache.count++;
            }

            print_start_event(&fresh);
        }
        else if(ev->what == PROC_EVENT_EXIT)
        {
            pid_t pid = ev->event_data.exit.process_pid;
            char pid_str[16];
            snprintf(pid_str, sizeof(pid_str), "%d", pid);

            int idx = find_by_pid(&cache, pid_str);
            if(idx >= 0)
            {
                print_exit_event(&cache.p[idx]);
                box_remove_at(&cache, idx);
            }
            else
            {
                printf("{\"event\":\"process_exit\",\"pid\":\"%s\",\"ts\":%ld}\n",
                       pid_str, now_seconds());
                fflush(stdout);
            }
        }
        /* PROC_EVENT_FORK is deliberately ignored here: the process
         * usually hasn't exec'd its real binary yet, so /proc/<pid>
         * would show it still looking like its parent. Waiting for
         * EXEC gives you accurate name/cmdline. If you need to catch
         * processes that fork and never exec, add a FORK case that
         * enriches from /proc but expect name==parent's name.
         */
    }

    close(sock_fd);
    box_free(&cache);
    return 0;
}