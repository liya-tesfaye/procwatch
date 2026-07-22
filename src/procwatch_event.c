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
#include <sys/inotify.h>
#include <sys/select.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

/* ------------------------------------------------------------------ */
/*  Configuration                                                       */
/* ------------------------------------------------------------------ */

#define INITIAL_CAP 10

static const char *WATCH_DIRS[] = {
    "/tmp",
    "/etc",
    "/bin",
    "/usr/bin",
    NULL   /* sentinel — add new paths here, nothing else needs changing */
};

/* Processes whose entire subtree we suppress.
 * If any ancestor of a new process matches one of these names, the
 * event is dropped.  Add noisy parents here — do NOT remove entries,
 * because that would re-introduce noise in the demo.                  */
static const char *SUPPRESS_ANCESTORS[] = {
    "code",           /* VS Code main process                          */
    "code-oss",       /* VS Code open-source build                     */
    "electron",       /* Electron shell (VS Code, etc.)                */
    "chrome",         /* Chrome / Chromium                             */
    "firefox",        /* Firefox                                       */
    NULL
};

/* ------------------------------------------------------------------ */
/*  Data structures                                                     */
/* ------------------------------------------------------------------ */

struct proc_info {
    char pid[16];
    char name[256];
    char ppid[16];
    char uid[16];
    char cmdline[1024];
};

struct proc_cache {
    struct proc_info *entries;
    int cap;
    int count;
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

static int is_num(const char *s)
{
    if(*s == '\0') return 0;
    while(*s)
    {
        if(!isdigit((unsigned char)*s)) return 0;
        s++;
    }
    return 1;
}

/* Write a JSON-safe string to stdout — escapes the five characters
 * that would otherwise break a JSON parser.                           */
static void emit_json_str(const char *s)
{
    while(*s)
    {
        switch(*s)
        {
            case '"':  printf("\\\""); break;
            case '\\': printf("\\\\"); break;
            case '\n': printf("\\n");  break;
            case '\r': printf("\\r");  break;
            case '\t': printf("\\t");  break;
            default:   putchar(*s);   break;
        }
        s++;
    }
}

static long now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long)ts.tv_sec;
}

/* ------------------------------------------------------------------ */
/*  Cache management                                                    */
/* ------------------------------------------------------------------ */

static int cache_init(struct proc_cache *c, int cap)
{
    c->entries = malloc((size_t)cap * sizeof(struct proc_info));
    if(!c->entries) return 0;
    c->cap   = cap;
    c->count = 0;
    return 1;
}

static int cache_grow(struct proc_cache *c)
{
    if(c->count < c->cap) return 1;

    int new_cap = c->cap * 2;
    struct proc_info *tmp = realloc(c->entries,
                                    (size_t)new_cap * sizeof(struct proc_info));
    if(!tmp)
    {
        free(c->entries);
        c->entries = NULL;
        fprintf(stderr, "sentineledr: realloc failed\n");
        return 0;
    }
    c->entries = tmp;
    c->cap     = new_cap;
    return 1;
}

static void cache_free(struct proc_cache *c)
{
    free(c->entries);
    c->entries = NULL;
    c->cap = c->count = 0;
}

static int cache_find(struct proc_cache *c, const char *pid)
{
    for(int i = 0; i < c->count; i++)
        if(strcmp(c->entries[i].pid, pid) == 0) return i;
    return -1;
}

/* Swap-with-last removal — O(1), order not preserved (fine for a cache) */
static void cache_remove(struct proc_cache *c, int idx)
{
    if(idx < 0 || idx >= c->count) return;
    c->entries[idx] = c->entries[c->count - 1];
    c->count--;
}

/* ------------------------------------------------------------------ */
/*  Noise filter                                                        */
/* ------------------------------------------------------------------ */

/* Walk the ancestor chain of `pid` (via the cache) and return 1 if
 * any ancestor's name matches SUPPRESS_ANCESTORS.
 * Stops after 16 hops to avoid infinite loops on pid 1.              */
static int should_suppress(const char *ppid_str, const struct proc_cache *c)
{
    char cur[16];
    strncpy(cur, ppid_str, sizeof(cur) - 1);
    cur[sizeof(cur) - 1] = '\0';

    for(int hop = 0; hop < 16; hop++)
    {
        if(strcmp(cur, "0") == 0 || strcmp(cur, "1") == 0) break;

        int idx = cache_find((struct proc_cache *)c, cur);
        if(idx < 0) break;

        const char *aname = c->entries[idx].name;
        for(int i = 0; SUPPRESS_ANCESTORS[i] != NULL; i++)
            if(strncmp(aname, SUPPRESS_ANCESTORS[i],
                       strlen(SUPPRESS_ANCESTORS[i])) == 0)
                return 1;

        strncpy(cur, c->entries[idx].ppid, sizeof(cur) - 1);
        cur[sizeof(cur) - 1] = '\0';
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  /proc enrichment                                                    */
/* ------------------------------------------------------------------ */

static int read_proc_status(const char *pid_str, struct proc_info *out)
{
    char path[512];
    snprintf(path, sizeof(path), "/proc/%s/status", pid_str);

    FILE *f = fopen(path, "r");
    if(!f) return 0;   /* process already gone — caller handles it */

    int got_name = 0, got_ppid = 0, got_uid = 0;
    char line[256];

    while(fgets(line, sizeof(line), f))
    {
        if     (!got_name && strncmp(line, "Name:", 5) == 0)
        {
            sscanf(line, "Name: %255s", out->name);
            strncpy(out->pid, pid_str, sizeof(out->pid) - 1);
            out->pid[sizeof(out->pid) - 1] = '\0';
            got_name = 1;
        }
        else if(!got_ppid && strncmp(line, "PPid:", 5) == 0)
        {
            sscanf(line, "PPid: %15s", out->ppid);
            got_ppid = 1;
        }
        else if(!got_uid && strncmp(line, "Uid:", 4) == 0)
        {
            sscanf(line, "Uid: %15s", out->uid);
            got_uid = 1;
        }
        if(got_name && got_ppid && got_uid) break;
    }
    fclose(f);
    return 1;
}

static void read_proc_cmdline(const char *pid_str, struct proc_info *out)
{
    char path[512];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);

    FILE *f = fopen(path, "r");
    if(!f) return;

    int len = (int)fread(out->cmdline, 1, sizeof(out->cmdline) - 1, f);
    fclose(f);

    if(len > 0)
    {
        out->cmdline[len] = '\0';
        /* /proc/PID/cmdline separates argv entries with NUL bytes —
         * replace them with spaces so the field is a readable string. */
        for(int i = 0; i < len - 1; i++)
            if(out->cmdline[i] == '\0') out->cmdline[i] = ' ';
    }
    else
    {
        /* Kernel threads have an empty cmdline — fall back to name.  */
        strncpy(out->cmdline, out->name, sizeof(out->cmdline) - 1);
        out->cmdline[sizeof(out->cmdline) - 1] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/*  Startup cache seed                                                  */
/* ------------------------------------------------------------------ */

/* Runs ONCE before the event loop.  Seeds the cache with processes
 * that were already running so EXIT events for them can be enriched.
 * No process_start events are emitted — these processes didn't just
 * start, the agent just started watching.                             */
static int seed_cache(struct proc_cache *cache)
{
    DIR *dir = opendir("/proc");
    if(!dir)
    {
        fprintf(stderr, "sentineledr: cannot open /proc\n");
        return 0;
    }

    struct dirent *ent;
    while((ent = readdir(dir)) != NULL)
    {
        if(!is_num(ent->d_name)) continue;
        if(!cache_grow(cache))  { closedir(dir); return 0; }

        struct proc_info *slot = &cache->entries[cache->count];
        memset(slot, 0, sizeof(*slot));

        if(!read_proc_status(ent->d_name, slot)) continue;
        read_proc_cmdline(ent->d_name, slot);
        cache->count++;
    }

    closedir(dir);
    return 1;
}

/* ------------------------------------------------------------------ */
/*  JSON emitters — stdout only, always flushed                        */
/* ------------------------------------------------------------------ */

static void emit_process_start(const struct proc_info *p)
{
    printf("{\"event\":\"process_start\","
           "\"pid\":%s,\"name\":\"", p->pid);
    emit_json_str(p->name);
    printf("\",\"ppid\":%s,\"uid\":%s,\"cmdline\":\"",
           p->ppid, p->uid);
    emit_json_str(p->cmdline);
    printf("\",\"ts\":%ld}\n", now_seconds());
    fflush(stdout);
}

static void emit_process_exit(const struct proc_info *p)
{
    printf("{\"event\":\"process_exit\","
           "\"pid\":%s,\"name\":\"", p->pid);
    emit_json_str(p->name);
    printf("\",\"ppid\":%s,\"uid\":%s,\"ts\":%ld}\n",
           p->ppid, p->uid, now_seconds());
    fflush(stdout);
}

/* Maps an inotify mask to a short event-type string */
static const char *inotify_event_name(uint32_t mask)
{
    if(mask & IN_CREATE)      return "file_create";
    if(mask & IN_DELETE)      return "file_delete";
    if(mask & IN_CLOSE_WRITE) return "file_write";
    if(mask & IN_MOVED_FROM)  return "file_moved_from";
    if(mask & IN_MOVED_TO)    return "file_moved_to";
    return "file_event";
}

static void emit_file_event(const char *dir, const struct inotify_event *ie)
{
    /* Skip events with no filename (happens for watches on plain files) */
    if(ie->len == 0) return;

    const char *type = inotify_event_name(ie->mask);
    int is_dir       = (ie->mask & IN_ISDIR) ? 1 : 0;

    printf("{\"event\":\"%s\",\"path\":\"", type);
    emit_json_str(dir);
    printf("/");
    emit_json_str(ie->name);
    printf("\",\"is_dir\":%s,\"ts\":%ld}\n",
           is_dir ? "true" : "false",
           now_seconds());
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/*  Netlink setup                                                       */
/* ------------------------------------------------------------------ */

struct proc_subscribe_msg {
    struct nlmsghdr nl_hdr;
    struct __attribute__((__packed__)) {
        struct cn_msg        cn_msg;
        enum proc_cn_mcast_op cn_mcast;
    };
} __attribute__((aligned(NLMSG_ALIGNTO)));

struct proc_event_msg {
    struct nlmsghdr nl_hdr;
    struct __attribute__((__packed__)) {
        struct cn_msg    cn_msg;
        struct proc_event proc_ev;
    };
} __attribute__((aligned(NLMSG_ALIGNTO)));

static int netlink_open(void)
{
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if(fd == -1) { perror("socket"); return -1; }

    struct sockaddr_nl addr = {0};
    addr.nl_family = AF_NETLINK;
    addr.nl_pid    = (unsigned)getpid();
    addr.nl_groups = CN_IDX_PROC;

    if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind");
        close(fd);
        return -1;
    }

    struct proc_subscribe_msg sub = {0};
    sub.nl_hdr.nlmsg_len  = sizeof(sub);
    sub.nl_hdr.nlmsg_pid  = (unsigned)getpid();
    sub.nl_hdr.nlmsg_type = NLMSG_DONE;
    sub.cn_msg.id.idx     = CN_IDX_PROC;
    sub.cn_msg.id.val     = CN_VAL_PROC;
    sub.cn_msg.len        = sizeof(enum proc_cn_mcast_op);
    sub.cn_mcast          = PROC_CN_MCAST_LISTEN;

    if(send(fd, &sub, sizeof(sub), 0) == -1)
    {
        perror("send (subscribe)");
        close(fd);
        return -1;
    }

    return fd;
}

/* ------------------------------------------------------------------ */
/*  Inotify setup                                                       */
/* ------------------------------------------------------------------ */

/* Returns the inotify fd, populates wd_out[] with one watch descriptor
 * per entry in WATCH_DIRS (matched by index).                         */
static int inotify_open(int *wd_out)
{
    int fd = inotify_init1(IN_NONBLOCK);
    if(fd == -1) { perror("inotify_init1"); return -1; }

    for(int i = 0; WATCH_DIRS[i] != NULL; i++)
    {
        wd_out[i] = inotify_add_watch(fd, WATCH_DIRS[i],
                        IN_CREATE      |
                        IN_DELETE      |
                        IN_MOVED_FROM  |
                        IN_MOVED_TO    |
                        IN_CLOSE_WRITE);

        if(wd_out[i] == -1)
            fprintf(stderr, "sentineledr: cannot watch %s: %m\n",
                    WATCH_DIRS[i]);
    }

    return fd;
}

/* Resolve a watch descriptor back to the directory path it covers.   */
static const char *wd_to_dir(const int *wds, int wd)
{
    for(int i = 0; WATCH_DIRS[i] != NULL; i++)
        if(wds[i] == wd) return WATCH_DIRS[i];
    return "(unknown)";
}

/* ------------------------------------------------------------------ */
/*  Inotify event draining                                              */
/* ------------------------------------------------------------------ */

/* inotify can batch multiple events in one read — drain the whole
 * buffer and emit a JSON line for each one.                           */
static void drain_inotify(int ifd, const int *wds)
{
    /* Buffer sized to hold several events; inotify_event has a
     * variable-length name field so we cast after alignment.          */
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    while(1)
    {
        ssize_t len = read(ifd, buf, sizeof(buf));
        if(len == -1) break;   /* EAGAIN/EWOULDBLOCK — buffer drained */

        const char *ptr = buf;
        const char *end = buf + len;

        while(ptr < end)
        {
            const struct inotify_event *ie =
                (const struct inotify_event *)ptr;

            emit_file_event(wd_to_dir(wds, ie->wd), ie);

            ptr += sizeof(struct inotify_event) + ie->len;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Netlink event handling                                              */
/* ------------------------------------------------------------------ */

static void handle_netlink(int sock_fd, struct proc_cache *cache)
{
    struct proc_event_msg msg;
    ssize_t recv_len = recv(sock_fd, &msg, sizeof(msg), 0);
    if(recv_len <= 0) return;

    struct proc_event *ev = &msg.proc_ev;

    if(ev->what == PROC_EVENT_EXEC)
    {
        char pid_str[16];
        snprintf(pid_str, sizeof(pid_str), "%d",
                 ev->event_data.exec.process_pid);

        struct proc_info fresh = {0};
        if(!read_proc_status(pid_str, &fresh)) return;
        read_proc_cmdline(pid_str, &fresh);

        /* Upsert into cache so a later EXIT has context.
         * We cache BEFORE the suppress check so that even suppressed
         * processes are tracked — their children need ancestor lookups. */
        int idx = cache_find(cache, pid_str);
        if(idx >= 0)
            cache->entries[idx] = fresh;
        else
        {
            if(!cache_grow(cache)) return;
            cache->entries[cache->count++] = fresh;
        }

        /* Drop events whose ancestor tree contains a suppressed process */
        if(should_suppress(fresh.ppid, cache)) return;

        emit_process_start(&fresh);
    }
    else if(ev->what == PROC_EVENT_EXIT)
    {
        char pid_str[16];
        snprintf(pid_str, sizeof(pid_str), "%d",
                 ev->event_data.exit.process_pid);

        int idx = cache_find(cache, pid_str);
        if(idx >= 0)
        {
            if(!should_suppress(cache->entries[idx].ppid, cache))
                emit_process_exit(&cache->entries[idx]);
            cache_remove(cache, idx);
        }
        /* Rare uncached exits: silently drop — no name/ppid to check,
         * and they're almost always from suppressed subtrees anyway.   */
    }
    /* PROC_EVENT_FORK intentionally skipped — the child hasn't exec'd
     * yet so /proc still shows the parent's name. EXEC arrives next
     * and gives accurate data. Add a FORK case only if you need to
     * catch processes that fork-and-never-exec (rare, mostly threads). */
}

/* ------------------------------------------------------------------ */
/*  main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    /* --- cache ---------------------------------------------------- */
    struct proc_cache cache;
    if(!cache_init(&cache, INITIAL_CAP))
    {
        fprintf(stderr, "sentineledr: out of memory\n");
        return 1;
    }
    if(!seed_cache(&cache))
    {
        cache_free(&cache);
        return 1;
    }

    /* --- netlink -------------------------------------------------- */
    int sock_fd = netlink_open();
    if(sock_fd == -1)
    {
        cache_free(&cache);
        return 1;
    }

    /* --- inotify -------------------------------------------------- */
    /* One watch descriptor per directory in WATCH_DIRS.              */
    int wds[sizeof(WATCH_DIRS) / sizeof(WATCH_DIRS[0])] = {0};
    int ifd = inotify_open(wds);
    if(ifd == -1)
    {
        close(sock_fd);
        cache_free(&cache);
        return 1;
    }

    /* --- event loop ----------------------------------------------- */
    int maxfd = sock_fd > ifd ? sock_fd : ifd;

    while(1)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock_fd, &rfds);
        FD_SET(ifd,     &rfds);

        if(select(maxfd + 1, &rfds, NULL, NULL, NULL) == -1)
        {
            perror("select");
            break;
        }

        if(FD_ISSET(sock_fd, &rfds))
            handle_netlink(sock_fd, &cache);

        if(FD_ISSET(ifd, &rfds))
            drain_inotify(ifd, wds);
    }

    /* --- cleanup -------------------------------------------------- */
    close(ifd);
    close(sock_fd);
    cache_free(&cache);
    return 0;
}