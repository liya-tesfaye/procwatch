# ProcWatch

Event-driven Linux process and filesystem telemetry agent, written in C.

ProcWatch monitors live system activity by tapping directly into the Linux kernel's event-notification interfaces — rather than polling — to detect process lifecycle events and filesystem changes in real time.

## Features

- **Netlink process event monitoring** — subscribes to the kernel's process connector (`NETLINK_CONNECTOR`) to receive fork/exec/exit events as they happen, with no polling delay
- **inotify filesystem monitoring** — watches target directories for file creation, modification, and deletion events
- **Unified event loop** — multiplexes both event sources (Netlink socket + inotify file descriptor) through a single `select()` loop
- **Process enrichment via `/proc`** — for each event, resolves executable path, parent PID, UID, and full command-line arguments from `/proc/[pid]/`
- **Structured JSON output** — every event is emitted as a structured JSON record, ready to feed into a log pipeline, SIEM, or downstream monitoring tool

## How It Works

1. Opens a Netlink socket bound to the kernel's process connector and subscribes to process events (`PROC_EVENT_FORK`, `PROC_EVENT_EXEC`, `PROC_EVENT_EXIT`)
2. Sets up `inotify` watches on configured directories
3. Runs a single-threaded `select()` loop multiplexing both file descriptors — no busy-waiting, no polling interval
4. On each event, enriches the raw PID/event data by reading `/proc/[pid]/status`, `/proc/[pid]/cmdline`, and `/proc/[pid]/exe`
5. Emits a structured JSON record per event to stdout (pipeable to a log collector)

## Build

```bash
gcc -o procwatch src/procwatch.c
```

## Usage

```bash
sudo ./procwatch
```

Requires root privileges to open the Netlink process-connector socket.

## Example Output

```json
{
  "event": "exec",
  "pid": 4821,
  "ppid": 4790,
  "uid": 1000,
  "exe": "/usr/bin/python3",
  "cmdline": "python3 scanner.py"
}
```

## Tech Stack

- C
- Linux Netlink sockets (`NETLINK_CONNECTOR`)
- inotify
- POSIX (`select()`, `/proc` filesystem)

## Roadmap

- [ ] eBPF-based syscall interception (replacing/augmenting Netlink for finer-grained visibility)
- [ ] Attack simulation module mapped to MITRE ATT&CK (privilege escalation, process injection, lateral movement)
- [ ] Configurable output sinks (file, syslog, network socket)

## Author

**Liya Tesfaye**
