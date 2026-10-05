# Ksnap web panel: intermediate layer and GUI

The panel is the third tier of Ksnap: a Flask REST API that drives the C engine
(`Ksnap-engine/build/Ksnap`) and a static browser frontend that talks only to
that API.

```
browser (HTML5 + Bootstrap 5 + vanilla JS)
    |  fetch(/api/...)
Flask API  (Ksnap-backend/src)
    |  subprocess: Ksnap -m Dump|Restore -p <pid> -d <dir> -n <name> [-k]
Ksnap engine (C, ptrace + /proc)
```

## Requirements

* `pip install -r Ksnap-web/Ksnap-backend/requirements.txt` (Flask, nothing else)
* the engine built: `cd Ksnap-engine && make`

That one dependency is the whole list; the API reads `/proc` and parses the
snapshot header with the standard library only.

## Running

The engine needs root (`ptrace`, `/proc/<pid>/mem`). Two supported modes:

**1. Unprivileged API + `sudo -n` (default).** Allow the engine without a
password by creating `/etc/sudoers.d/ksnap` (`sudo visudo -f /etc/sudoers.d/ksnap`):

The second line is only needed for the *Stop restored process* button, because
the restored process runs as root and cannot be signalled by an ordinary user.
Then:

```
python3 Ksnap-web/Ksnap-backend/src/app.py
```

**2. Whole API as root.** No sudoers entry, but the HTTP server itself runs as
root (it binds `127.0.0.1` only):

```
sudo KSNAP_SUDO=0 python3 Ksnap-web/Ksnap-backend/src/app.py
```

Open <http://127.0.0.1:5000>.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `KSNAP_ENGINE` | `Ksnap-engine/build/Ksnap` | path to the engine binary |
| `KSNAP_SNAPSHOT_DIR` | `Ksnap-engine/save` | default snapshot store (`-d` of the engine) |
| `KSNAP_DIRECTORIES_FILE` | `<snapshot store>/directories.json` | other folders a dump was written to |
| `KSNAP_SUDO` | `auto` | `auto` = sudo unless already root, `1` = always, `0` = never |
| `KSNAP_HOST` / `KSNAP_PORT` | `127.0.0.1` / `5000` | where the panel listens |
| `KSNAP_DUMP_TIMEOUT` | `60` | seconds before a dump is abandoned |
| `KSNAP_LOG_CAPACITY` | `2000` | console lines kept in memory |
| `KSNAP_CHECK_TIMEOUT` | `15` | seconds before an eligibility check is abandoned |
| `KSNAP_MAX_SNAPSHOT_MB` | `512` | above this a snapshot is flagged partial, not refused |

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/status` | engine availability, privilege mode, restore session |
| `GET` | `/api/processes?query=&all=` | processes with the engine's verdict, see Eligibility |
| `GET` | `/api/snapshots` | snapshots of every known folder with parsed headers, each with its `directory`, plus `directories` |
| `DELETE` | `/api/snapshots/<name>?directory=<folder>` | remove one snapshot |
| `POST` | `/api/dump` | `{"pid": 1234, "name": "counter-1234", "directory": "/data/ksnap", "kill": false}`, `kill: true` ends the process with the snapshot (`-k`) |
| `POST` | `/api/restore` | `{"name": "counter-1234.ksnap", "directory": "/data/ksnap"}` |
| `POST` | `/api/restore/stop` | terminate the running restored process |
| `GET` | `/api/logs?since=<seq>` | console feed since a sequence number |
| `DELETE` | `/api/logs` | clear the console |

Errors are always `{"error": "..."}`: `400` for a rejected argument, `404` for a
missing snapshot, `409` when the engine cannot do it right now.

A dump can go to any absolute folder, which is created when it is missing. The
default store and every folder a dump was written to are remembered in
`KSNAP_DIRECTORIES_FILE`, and restore and delete only accept those folders, so
the API never touches a folder it did not write to itself. Leaving `directory`
out means the default store.

The name given to `-n` is validated (`[A-Za-z0-9._-]{1,64}` plus a containment
check against the snapshot directory) and every call is executed as an argument
list, never through a shell.

## Eligibility

The engine attaches to whatever it is given and fails, or loses state quietly,
when the target is outside its scope. So before anything is written the panel
asks it: `Ksnap -m Check` reports, as one JSON object per process, whether a
dump and a restore would work. The contract is documented in
`Ksnap-engine/docs/markdown/check_mode.md`.

The panel does **not** reimplement those rules. It used to, as a transcription
of `dumper.c` into Python, and that copy could drift from the engine without a
test noticing. What is left in `eligibility.py` is only the judgement the
engine has no opinion about: a process can come back and still not be the same
process.

| Level | Decided by | Meaning | In the panel |
| --- | --- | --- | --- |
| `ok` | engine | takes it, restore is faithful | listed, snapshot allowed |
| `risky` | panel | takes it, but the process comes back different | listed with a badge, caveats before the dump and in the console |
| `blocked` | engine | refuses it, with its own reason | hidden until *Show all*, snapshot refused with `400` |
| `unknown` | panel | the engine could not be asked | listed as not checked, snapshot refused |

There is deliberately no fallback set of rules for the `unknown` case. If the
engine is not built, every row says so and the dump fails on the missing binary
anyway, which is honest; a second copy of the rules would recreate exactly the
problem this split removed.

### What the engine refuses

`multi_threaded`, `zombie`, `already_traced`, `ptrace_refused`,
`kernel_thread`, `exe_unreadable`, `exe_deleted`, `exe_not_executable`,
`shared_mapping`, `device_mapping`, `too_many_kernel_maps`,
`no_dumpable_mapping`, `not_inspectable`, `gone`. Each one is explained in
`check_mode.md`, next to the place in the C source it comes from.

Only the listing is a cheap answer. Before a dump the panel asks about that one
process, which also runs the engine's ptrace probe, so a process the list
called `ok` can still be refused at the gate with `ptrace_refused`.

### What the panel adds

| code | From the fact | Why it only warns |
| --- | --- | --- |
| `arguments_not_restored` | `argc > 1` | the restore execs `argv = {exe_path}`, so the process starts without its arguments |
| `open_files` | `open_fds`, `volatile_fds` | descriptors are not in the snapshot, the restored process gets the engine's stdio |
| `has_children` | `children` | children are neither dumped nor restored |
| `large_snapshot` | `snapshot_bytes` over `KSNAP_MAX_SNAPSHOT_MB` | a big snapshot is a big file, not a failure |
| `path_with_space` | a space in `exe` | the maps parser scans paths with `%s` |

Kernel threads never reach the listing, because they own no address space; the
response reports how many were skipped in `kernel_threads`.

## Restore sessions

`Ksnap -m Restore` waits for the process it brought back (`waitpid` in
`src/restorer.c`), so the API keeps it as a *session*: its merged stdout/stderr
is the restored program's own output and is streamed into the console. Only one
session can run at a time, because restores replay fixed addresses and two
would collide.

## Tests

```
python3 -m unittest discover -s Ksnap-web/Ksnap-backend/tests -t Ksnap-web/Ksnap-backend/tests
```

These run without the engine: the Check output it would produce is canned in
`tests/test_check.py`, so the panel is tested against the contract rather than
against a build. The engine has its own tests, which do need root:

```
cd Ksnap-engine && make test
```

`.github/workflows/ci.yml` runs exactly these two commands, plus a build with
`-Werror` and a `clang-format` check, on every push to `devel` or `main` and on
every pull request to `main`. Nothing in CI is unavailable locally, so a red
check can always be reproduced with the commands above.

## Known limitations (MVP scope of the engine)

The engine reports these through Check rather than discovering them mid dump:

* single threaded processes only (`multi_threaded`)
* shared memory and device mappings are not carried over (`shared_mapping`,
  `device_mapping`)
* file descriptors, sockets, process trees and the working directory are not
  restored (`open_files`, `has_children`)
* a restored process is started from the snapshot's own executable path, with
  no command line arguments (`arguments_not_restored`)
* a snapshot only restores on the kernel it was taken on, because the vdso has
  to match, and on a CPU with the same extended features (AVX, AVX-512, ...),
  because the FPU/SSE/AVX state is stored as the XSAVE area of the dumping CPU
* snapshots taken before format version 3 (no FPU/SSE/AVX state) are listed
  with an error and cannot be restored, they have to be taken again
