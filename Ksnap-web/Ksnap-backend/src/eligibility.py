import config
import engine
import processes

OK = "ok"
RISKY = "risky"
BLOCKED = "blocked"
UNKNOWN = "unknown"

_SEVERITY = {OK: 0, RISKY: 1, BLOCKED: 2}


def _reason(code, level, message):
    return {"code": code, "level": level, "message": message}


def _caveats(facts):
    """What the engine reports as facts, read as risks to the restore."""
    reasons = []

    # the restore execs the binary as argv = {exe_path, NULL}, see
    # Ksnap-engine/src/restorer.c
    if facts.get("argc", 0) > 1:
        reasons.append(
            _reason(
                "arguments_not_restored",
                RISKY,
                "command line arguments are not stored in the snapshot, the "
                "process is restarted without them",
            )
        )

    volatile = facts.get("volatile_fds", 0)
    extra = facts.get("open_fds", 0)
    if extra:
        details = []
        if volatile:
            details.append("%d socket(s) or pipe(s)" % volatile)
        if extra - volatile > 0:
            details.append("%d open file(s)" % (extra - volatile))
        reasons.append(
            _reason(
                "open_files",
                RISKY,
                "the snapshot stores no descriptors, so %s are lost on restore"
                % " and ".join(details),
            )
        )

    if facts.get("children", 0):
        reasons.append(
            _reason(
                "has_children",
                RISKY,
                "the process has %d child process(es), which are neither "
                "dumped nor restored" % facts["children"],
            )
        )

    # the engine counted the payload exactly, so this is the real file size
    snapshot_mb = facts.get("snapshot_bytes", 0) // (1024 * 1024)
    if snapshot_mb > config.MAX_SNAPSHOT_MB:
        reasons.append(
            _reason(
                "large_snapshot",
                RISKY,
                "the snapshot would hold %d MiB of memory" % snapshot_mb,
            )
        )

    # parse_maps_line in Ksnap-engine/src/maps.c scans paths with %s
    if " " in facts.get("exe", ""):
        reasons.append(
            _reason(
                "path_with_space",
                RISKY,
                "the executable path contains a space, which the engine maps "
                "parser truncates",
            )
        )

    return reasons


def verdict_from_report(report):
    """One report from 'Ksnap -m Check' as a verdict the panel can render."""
    if report is None:
        return unavailable("the engine did not report on this process")

    facts = report.get("facts", {})

    # the engine already decided, so its reasons are taken as they are
    reasons = [
        _reason(item["code"], BLOCKED, item.get("detail") or item["code"])
        for item in report.get("reasons", [])
    ]
    if not report.get("dumpable", False) and not reasons:
        reasons.append(
            _reason("blocked", BLOCKED, "the engine refused without a reason")
        )

    reasons += _caveats(facts)
    reasons.sort(key=lambda item: -_SEVERITY[item["level"]])

    level = reasons[0]["level"] if reasons else OK
    return {"level": level, "reasons": reasons, "source": "engine", "facts": facts}


def unavailable(message):
    """The verdict for a process the engine could not be asked about."""
    return {
        "level": UNKNOWN,
        "reasons": [_reason("not_checked", UNKNOWN, message)],
        "source": "unavailable",
        "facts": {},
    }


def verdicts_for(found):
    """Attach a verdict to every process in *found*, in place.

    One engine call covers the whole listing. When the engine cannot be run the
    panel says so on every row instead of guessing: there is deliberately no
    second set of rules here to fall back on.
    """
    try:
        reports = engine.check()
    except engine.EngineError as error:
        for process in found:
            process["eligibility"] = unavailable(str(error))
        return found

    for process in found:
        process["eligibility"] = verdict_from_report(reports.get(process["pid"]))
    return found


def require_dumpable(pid):
    """The engine's verdict for *pid*, refusing what it cannot handle.

    This is the gate in front of a dump, so it asks about the one process. The
    engine then also runs its ptrace probe, which no amount of reading /proc
    can replace.
    """
    pid = int(pid)
    verdict = verdict_from_report(engine.check(pid).get(pid))

    if verdict["level"] in (BLOCKED, UNKNOWN):
        raise processes.ProcessError(
            "pid %d cannot be snapshotted: %s"
            % (pid, "; ".join(describe(verdict, verdict["level"])))
        )

    return verdict


def count_levels(found):
    """How many of *found* sit at each level."""
    counts = {OK: 0, RISKY: 0, BLOCKED: 0, UNKNOWN: 0}
    for process in found:
        counts[process["eligibility"]["level"]] += 1
    return counts


def describe(verdict, level=None):
    """The reason messages of *verdict*, optionally only one level of them."""
    return [
        reason["message"]
        for reason in verdict["reasons"]
        if level is None or reason["level"] == level
    ]
