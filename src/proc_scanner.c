#define _POSIX_C_SOURCE 199309L 
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

int is_num(char *name)
{
    int i = 0;
    while(name[i] != '\0')
    {
        if(isdigit(name[i]) == 0)
            return 0;
        i++;
    }
    return 1;
}

void print_json_str(const char *s) {
    while(*s) {
        if(*s == '"')       printf("\\\"");
        else if(*s == '\\') printf("\\\\");
        else if(*s == '\n') printf("\\n");
        else if(*s == '\r') printf("\\r");
        else if(*s == '\t') printf("\\t");
        else                putchar(*s);
        s++;
    }
}

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

int main()
{
    struct dirent *entry;
    DIR *dir;
    struct timespec sleep_ts;
    sleep_ts.tv_sec = 0;
    sleep_ts.tv_nsec = 500000000L;
    struct timespec now;
    
    struct box arr;
    struct box p_arr;
    p_arr.cap = 10;
    p_arr.count = 0;
    p_arr.p = malloc(p_arr.cap * sizeof(struct list));

    int first_scan = 1;

    while(1)
    {
        arr.cap = 10;
        arr.count = 0;
        arr.p = malloc(arr.cap * sizeof(struct list));

        dir = opendir("/proc");
        if(dir == NULL)
        {
            printf("Couldn't open directory");
            return 1;
        }

        while((entry = readdir(dir)) != NULL)
        {
            if(is_num(entry->d_name) == 1)
            {
                char path[512];
                snprintf(path, sizeof(path), "/proc/%s/status", entry->d_name);

                FILE *f = fopen(path, "r");
                if(f == NULL)
                    continue;

                if(arr.count == arr.cap)
                {
                    arr.cap = 2 * arr.cap;
                    struct list *temp = realloc(arr.p, arr.cap * sizeof(struct list));
                    if(temp == NULL)
                    {
                        free(arr.p);
                        fprintf(stderr, "realloc failed\n");
                        return 1;
                    }
                    arr.p = temp;
                }

                int got_name = 0, got_ppid = 0, got_uid = 0;
                char line[256];

                while(fgets(line, sizeof(line), f))
                {
                    if(strncmp(line, "Name:", 5) == 0)
                    {
                        sscanf(line, "Name: %255s", arr.p[arr.count].name);
                        strncpy(arr.p[arr.count].pid, entry->d_name, sizeof(arr.p[arr.count].pid) - 1);
                        arr.p[arr.count].pid[sizeof(arr.p[arr.count].pid) - 1] = '\0';
                        got_name = 1;
                    }
                    else if(strncmp(line, "PPid:", 5) == 0)
                    {
                        sscanf(line, "PPid: %15s", arr.p[arr.count].ppid);
                        got_ppid = 1;
                    }
                    else if(strncmp(line, "Uid:", 4) == 0)
                    {
                        sscanf(line, "Uid: %15s", arr.p[arr.count].uid);
                        got_uid = 1;
                    }
                    if(got_name && got_ppid && got_uid) break;
                }
                fclose(f);       

                char cmd_path[512];
                snprintf(cmd_path,sizeof(cmd_path), "/proc/%s/cmdline", entry->d_name);
                FILE *cf = fopen(cmd_path, "r");
                if(cf != NULL){
                    int len = fread(arr.p[arr.count].cmdline,1,sizeof(arr.p[arr.count].cmdline) - 1, cf);
                    fclose(cf);
                    if(len > 0)
                    {
                        arr.p[arr.count].cmdline[len] = '\0';
                        for(int i = 0; i < len -1; i++)
                        {
                            if(arr.p[arr.count].cmdline[i] == '\0')
                                arr.p[arr.count].cmdline[i] = ' ';
                        }
                    } else {
                        strncpy(arr.p[arr.count].cmdline, arr.p[arr.count].name, sizeof(arr.p[arr.count].cmdline) -1);
                        arr.p[arr.count].cmdline[sizeof(arr.p[arr.count].cmdline) -1] = '\0';
                    }
                }
                arr.count++;     
            }
        }

        if(first_scan == 0)
        {
            for(int k = 0; k < arr.count; k++)
            {
                int found = 0;
                for(int m = 0; m < p_arr.count; m++)
                {
                    if(strcmp(arr.p[k].pid, p_arr.p[m].pid) == 0)
                    {
                        found = 1;
                        break;
                    }
                }
                if(found == 0)
                {
                    clock_gettime(CLOCK_REALTIME, &now);
                    printf("{\"event\":\"process_start\",\"pid\":%s,\"name\":\"", arr.p[k].pid);
                    print_json_str(arr.p[k].name);
                    printf("\",\"ppid\":%s,\"uid\":%s,\"cmdline\":\"", arr.p[k].ppid, arr.p[k].uid);
                    print_json_str(arr.p[k].cmdline);
                    printf("\",\"ts\":%ld}\n", (long)now.tv_sec);
                }
            }

            for(int k = 0; k < p_arr.count; k++)
            {
                int exist = 0;
                for(int m = 0; m < arr.count; m++)
                {
                    if(strcmp(p_arr.p[k].pid, arr.p[m].pid) == 0)
                    {
                        exist = 1;
                        break;
                    }
                }
                if(exist == 0)
                {
                    clock_gettime(CLOCK_REALTIME, &now);
                    printf("{\"event\":\"process_exit\",\"pid\":%s,\"name\":\"", p_arr.p[k].pid);
                    print_json_str(p_arr.p[k].name);
                    printf("\",\"ppid\":%s,\"uid\":%s,\"ts\":%ld}\n",
                        p_arr.p[k].ppid, p_arr.p[k].uid, (long)now.tv_sec);
                }
            }
        }

        if(arr.count > p_arr.cap)
        {
            p_arr.cap = arr.cap;
            struct list *temp = realloc(p_arr.p, p_arr.cap * sizeof(struct list));
            if(temp == NULL)
            {
                free(p_arr.p);
                fprintf(stderr, "realloc failed\n");
                return 1;
            }
            p_arr.p = temp;
        }

        for(int i = 0; i < arr.count; i++)
        {
            strncpy(p_arr.p[i].pid,  arr.p[i].pid,  sizeof(p_arr.p[i].pid)  - 1);
            p_arr.p[i].pid[sizeof(p_arr.p[i].pid)   - 1] = '\0';
            strncpy(p_arr.p[i].name, arr.p[i].name, sizeof(p_arr.p[i].name) - 1);
            p_arr.p[i].name[sizeof(p_arr.p[i].name) - 1] = '\0';
            strncpy(p_arr.p[i].ppid, arr.p[i].ppid, sizeof(p_arr.p[i].ppid) - 1);
            p_arr.p[i].ppid[sizeof(p_arr.p[i].ppid) - 1] = '\0';
            strncpy(p_arr.p[i].uid,  arr.p[i].uid,  sizeof(p_arr.p[i].uid)  - 1);
            p_arr.p[i].uid[sizeof(p_arr.p[i].uid)   - 1] = '\0';
        }

        p_arr.count = arr.count;
        first_scan = 0;
        free(arr.p);
        closedir(dir);
        nanosleep(&sleep_ts, NULL);
    }

    return 0;
}