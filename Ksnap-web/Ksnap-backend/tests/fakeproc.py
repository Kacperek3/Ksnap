"""Builds a fake /proc tree on disk for the process and eligibility tests.

Every function under test takes a proc= directory, so the tests write real
files instead of patching os and pathlib. The defaults describe the case the
engine is known to handle: a single threaded, statically linked program like
Ksnap-engine/test_programs/counter_static_noPie.
"""

import os
from pathlib import Path

# the shape of /proc/<pid>/maps for a static non PIE binary, which is what
# test/test_static_noPie.sh dumps and restores successfully
DEFAULT_MAPS = """\
00400000-00401000 r--p 00000000 08:02 262401 {exe}
00401000-00402000 r-xp 00001000 08:02 262401 {exe}
00402000-00403000 rw-p 00002000 08:02 262401 {exe}
00403000-00424000 rw-p 00000000 00:00 0 [heap]
7ffff7ff9000-7ffff7ffd000 r--p 00000000 00:00 0 [vvar]
7ffff7ffd000-7ffff7fff000 r-xp 00000000 00:00 0 [vdso]
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]
"""


def fake_proc(
    directory,
    pid,
    comm="counter",
    state="S",
    threads=1,
    cmdline="/bin/counter",
    rss_kb=2048,
    uid=None,
    tracer_pid=0,
    exe="counter",
    maps=None,
    fds=None,
    children=(),
):
    """Create /proc/<pid> under *directory* and return its path.

    exe      basename of an executable created next to the tree, an absolute
             path used verbatim, or None to leave out /proc/<pid>/exe
    maps     contents of /proc/<pid>/maps, defaults to DEFAULT_MAPS
    fds      {name: target} for /proc/<pid>/fd, defaults to stdio on /dev/null
    children pids written into /proc/<pid>/task/<pid>/children
    """
    root = Path(directory)
    entry = root / str(pid)
    entry.mkdir()
    uid = os.getuid() if uid is None else uid

    # /proc/<pid>/stat: "pid (comm) state ...", num_threads is the 20th field
    # overall, which is index 17 once pid and comm are consumed
    fields = ["0"] * 18
    fields[0] = state
    fields[17] = str(threads)
    (entry / "stat").write_text("%d (%s) %s\n" % (pid, comm, " ".join(fields)))
    (entry / "cmdline").write_text(cmdline.replace(" ", "\x00") + "\x00" if cmdline else "")
    (entry / "status").write_text(
        "Name:\t%s\nUid:\t%d\t%d\t%d\t%d\nVmRSS:\t%d kB\nTracerPid:\t%d\n"
        % (comm, uid, uid, uid, uid, rss_kb, tracer_pid)
    )

    # exe=None leaves no symlink at all, which is what readlink fails on for a
    # kernel thread
    executable = _make_executable(root, exe)
    if executable is not None:
        (entry / "exe").symlink_to(executable)

    (entry / "maps").write_text(
        DEFAULT_MAPS.format(exe=executable or "/bin/counter") if maps is None else maps
    )

    descriptors = {"0": "/dev/null", "1": "/dev/null", "2": "/dev/null"}
    descriptors.update(fds or {})
    fd_dir = entry / "fd"
    fd_dir.mkdir()
    for name, target in descriptors.items():
        (fd_dir / name).symlink_to(target)

    task = entry / "task" / str(pid)
    task.mkdir(parents=True)
    (task / "children").write_text(" ".join(str(child) for child in children))

    return entry


def _make_executable(root, exe):
    """The path /proc/<pid>/exe should point at, created when it is relative."""
    if exe is None:
        return None
    if os.path.isabs(exe):
        return exe
    path = root / exe
    if not path.exists():
        path.write_bytes(b"\x7fELF")
        path.chmod(0o755)
    return str(path)
