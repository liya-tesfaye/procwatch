# ProcWatch

A lightweight host-based intrusion detection agent for Linux.

## Overview

ProcWatch is a lightweight Linux process monitoring agent written in C. It scans the `/proc` filesystem every 500ms to track active processes and detect changes in the system process list. Events are output as structured JSON for easy parsing and integration.

## Current Status (Week 1)

### Initial foundation
- Reads `/proc/[pid]/status` for active processes
- Extracts PID and process name
- Polls the system every 500ms
- Detects newly created and exited processes
- Outputs events to stdout

### Week 1 improvements
- Added `PPid` and `Uid` fields read from `/proc/[pid]/status`
- Added full command line read from `/proc/[pid]/cmdline` using `fread` (handles null-separated arguments)
- Added Unix timestamps to every event via `clock_gettime`
- Switched output from plain text to structured JSON:
```json
{"event":"process_start","pid":1234,"name":"bash","ppid":998,"uid":1000,"cmdline":"bash","ts":1748822400}
{"event":"process_exit","pid":1234,"name":"bash","ppid":998,"uid":1000,"ts":1748822401}
```
- Fixed `realloc` bug: now returns error instead of falling through on NULL
- Replaced all `strcpy` with `strncpy` and explicit null termination
- Fixed `arr.count++` and `fclose` placement (were incorrectly inside the `fgets` loop)
- Added `_POSIX_C_SOURCE 199309L` for portable POSIX compliance

## Build

```bash
gcc -Wall -Wextra -o proc_scanner src/proc_scanner.c
```

## Run

```bash
./proc_scanner          # plain JSON output
./proc_scanner | jq .   # pretty-printed
```

## Install

```bash
sudo mv proc_scanner /usr/local/bin/
sudo chmod +x /usr/local/bin/proc_scanner
```

## Notes

- Uses polling-based monitoring of `/proc` — no kernel modules required
- Maintains two in-memory snapshots and diffs them each interval
- Kernel threads (empty cmdline) fall back to process name
- Designed for Linux only
