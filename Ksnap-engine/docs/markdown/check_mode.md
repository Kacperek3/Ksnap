# Check mode

`Ksnap -m Check` answers, before anything is written, whether this engine can
dump and restore a process.

It exists because the question used to be answered twice. The web panel had the
rules of the dumper transcribed into Python, which meant a change to
`is_dumpable_path` in C would make the panel lie without any test noticing.
The engine is the only component that knows what it copies, so it is the only
component that should answer.

**This is an interface between two components.** The panel parses this output
(`Ksnap-web/Ksnap-backend/src/engine.py`), so renaming a field or a reason code
is an API change, not an internal one.

## Usage

```
Ksnap -m Check -p <pid>    one report for that process
Ksnap -m Check             one report per process in /proc
```

Both need root for anything they do not own, the same as Dump. Output is one
JSON object per line, so it can be read as a stream and a single unparsable
line never costs the whole sweep.

| Exit code | Meaning |
| --- | --- |
| `0` | the process is dumpable, or the sweep finished |
| `11` | the process is not dumpable, which is an answer, not a failure |
| `1` | the tool could not do its job: bad arguments, `/proc` unreadable |

The distinction between `11` and `1` matters to the caller: one means "pick a
different process", the other means "something is wrong with the setup".

## Output

```json
{"pid":18064,"dumpable":true,"reasons":[],"facts":{"comm":"counter_static_","state":"S","threads":1,"tracer_pid":0,"uid":1000,"rss_kb":772,"argc":1,"exe":"/opt/counter","open_fds":0,"volatile_fds":0,"children":0,"dumpable_vmas":8,"kernel_maps":3,"shared_vmas":0,"device_vmas":0,"snapshot_bytes":1052672,"ptrace_probed":true,"ptrace_ok":true}}
```

`dumpable` is `true` exactly when `reasons` is empty.

The field is not called `level`, because the engine deliberately has no opinion
on whether a restore would be *faithful*. It reports facts and refusals; the
panel turns those into its own three levels (`Ksnap-web/Ksnap-backend/src/eligibility.py`).

### facts

| Field | Meaning |
| --- | --- |
| `comm`, `state`, `threads`, `tracer_pid`, `uid`, `rss_kb` | one pass over `/proc/<pid>/status` |
| `argc` | arguments in `/proc/<pid>/cmdline`, `0` marks a kernel thread |
| `exe` | `/proc/<pid>/exe`, with the ` (deleted)` suffix stripped |
| `open_fds` | descriptors besides 0, 1 and 2 |
| `volatile_fds` | of those, the ones behind `socket:`, `pipe:` or `anon_inode:` |
| `children` | entries in `/proc/<pid>/task/<pid>/children` |
| `dumpable_vmas`, `kernel_maps`, `shared_vmas`, `device_vmas` | mappings per class, from `classify_maps_line` |
| `snapshot_bytes` | **what the payload of the snapshot would weigh**, the sum of the dumpable mappings |
| `ptrace_probed`, `ptrace_ok` | whether the ptrace probe ran, and whether it worked |

`snapshot_bytes` is the exact size the dump will write after the header, the
descriptor table, the path pool and the XSAVE area (FPU/SSE/AVX state), which
is why `Ksnap-engine/test/test_check.sh` asserts it against a real dump. That
assertion is what keeps Check and Dump from drifting apart.

### reasons

Every reason means `dumpable: false`. `code` is stable and meant to be matched
on, `detail` is for a person to read.

| Code | Why the engine refuses |
| --- | --- |
| `multi_threaded` | `PTRACE_SEIZE` takes the main thread only, so the others would keep changing memory while it is copied, and the restore brings back one thread |
| `zombie` | no address space left |
| `already_traced` | `ptrace` allows a single tracer, and somebody else holds this one |
| `ptrace_refused` | the probe failed: no permission, `yama.ptrace_scope`, or the process would not stop |
| `kernel_thread` | no memory of its own to snapshot |
| `exe_unreadable` | `/proc/<pid>/exe` does not resolve |
| `exe_deleted` | the binary is gone, so the restore could not exec it |
| `exe_not_executable` | the binary cannot be run by the engine |
| `shared_mapping` | the dumper drops `MAP_SHARED` mappings silently, so the restored process would reach for memory that is not there |
| `device_mapping` | a `/dev/*` mapping cannot be read through `/proc/<pid>/mem`, and a failed read aborts the dump |
| `too_many_kernel_maps` | the header holds `KSNAP_MAX_KERNEL_MAPS` of them |
| `no_dumpable_mapping` | nothing the engine would copy |
| `not_inspectable` | `/proc` of this process is closed to the engine, run it as root |
| `gone` | the process exited while it was being inspected |

## The ptrace probe

With `-p`, Check runs the first four steps of a dump and undoes them:
`PTRACE_SEIZE`, `PTRACE_INTERRUPT`, `waitpid`, `PTRACE_DETACH`. That is the
only way to answer "would a dump attach at all", because permission depends on
`yama.ptrace_scope` and on who else is tracing, which no amount of reading
`/proc` reveals.

It is deliberately cheap: `PTRACE_SEIZE` on its own does not stop the target,
the stop from `PTRACE_INTERRUPT` lasts only until the detach a moment later,
and the kernel detaches automatically if the engine dies in between.

**The sweep does not probe.** Touching several hundred processes every time a
list is refreshed is not worth it, so `ptrace_probed` is `false` there. A
process can therefore be reported dumpable by the sweep and then refused with
`ptrace_refused` when it is checked individually before a dump. That is the
intended order: the cheap answer for the list, the certain one at the gate.

## Where the rules live

`classify_maps_line` in `src/maps.c` is the single place that decides what
happens to one mapping. Both `collect_vmas` in `src/dumper.c` and `scan_maps`
in `src/checker.c` go through it, so Check cannot disagree with Dump about
which mappings matter.
