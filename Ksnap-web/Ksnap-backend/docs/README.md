# Ksnap web panel: intermediate layer and GUI

The panel is the third tier of Ksnap: a Flask REST API that drives the C engine
(`Ksnap-engine/build/Ksnap`) and a static browser frontend that talks only to
that API.

```
browser (HTML5 + Bootstrap 5 + vanilla JS)
    |  fetch(/api/...)
Flask API  (Ksnap-backend/src)
    |  subprocess: Ksnap -m Dump|Restore -p <pid> -d <dir> -n <name>
Ksnap engine (C, ptrace + /proc)
```

## Requirements

* Python 3 with Flask (`python3 -c "import flask"` must succeed)
* the engine built: `cd Ksnap-engine && make`

There are no other dependencies; the API reads `/proc` and parses the snapshot
header with the standard library only.

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
| `KSNAP_SNAPSHOT_DIR` | `Ksnap-engine/save` | snapshot store (`-d` of the engine) |
| `KSNAP_SUDO` | `auto` | `auto` = sudo unless already root, `1` = always, `0` = never |
| `KSNAP_HOST` / `KSNAP_PORT` | `127.0.0.1` / `5000` | where the panel listens |
| `KSNAP_DUMP_TIMEOUT` | `60` | seconds before a dump is abandoned |
| `KSNAP_LOG_CAPACITY` | `2000` | console lines kept in memory |

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/status` | engine availability, privilege mode, restore session |
| `GET` | `/api/processes?query=` | dumpable processes from `/proc` |
| `GET` | `/api/snapshots` | snapshot store with parsed headers |
| `DELETE` | `/api/snapshots/<name>` | remove one snapshot |
| `POST` | `/api/dump` | `{"pid": 1234, "name": "counter-1234"}` |
| `POST` | `/api/restore` | `{"name": "counter-1234.ksnap"}` |
| `POST` | `/api/restore/stop` | terminate the running restored process |
| `GET` | `/api/logs?since=<seq>` | console feed since a sequence number |
| `DELETE` | `/api/logs` | clear the console |

Errors are always `{"error": "..."}`: `400` for a rejected argument, `404` for a
missing snapshot, `409` when the engine cannot do it right now.

The name given to `-n` is validated (`[A-Za-z0-9._-]{1,64}` plus a containment
check against the snapshot directory) and every call is executed as an argument
list, never through a shell.

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

## Known limitations (MVP scope of the engine)

* single-threaded processes only; multi-threaded ones are listed with a warning
* open file descriptors, process trees and sockets are not restored
* a restored process is started from the snapshot's own executable path
