"""The contract with 'Ksnap -m Check' and the risk layer on top of it.

The engine itself is tested from Ksnap-engine/test/test_check.sh, which runs
the real binary. Here the engine is replaced by canned output, so these tests
pin the parsing, the verdict collapse and what happens when the engine lies,
crashes or is missing.
"""

import json
import subprocess
import unittest
from unittest import mock

import context  # noqa: F401

import config
import eligibility
import engine
import processes


def report(pid=4321, dumpable=True, reasons=(), **facts):
    """One line of Check output, with the fields the engine always emits."""
    defaults = {
        "comm": "counter",
        "state": "S",
        "threads": 1,
        "tracer_pid": 0,
        "uid": 1000,
        "rss_kb": 2048,
        "argc": 1,
        "exe": "/bin/counter",
        "open_fds": 0,
        "volatile_fds": 0,
        "children": 0,
        "dumpable_vmas": 8,
        "kernel_maps": 3,
        "shared_vmas": 0,
        "device_vmas": 0,
        "snapshot_bytes": 1052672,
        "ptrace_probed": True,
        "ptrace_ok": True,
    }
    defaults.update(facts)
    return {
        "pid": pid,
        "dumpable": dumpable,
        "reasons": list(reasons),
        "facts": defaults,
    }


def completed(reports, returncode=0, stderr=""):
    stdout = "".join(json.dumps(item) + "\n" for item in reports)
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class EngineCheckTest(unittest.TestCase):
    """engine.check(): the argv it builds and the output it accepts."""

    def setUp(self):
        engine.logbook.clear()
        # the same pattern the dump tests use: the binary check is bypassed and
        # only the argv matters
        patched = mock.patch.object(engine, "_binary", return_value="/opt/Ksnap")
        patched.start()
        self.addCleanup(patched.stop)

    def run_check(self, result, pid=None):
        with mock.patch.object(config, "uses_sudo", return_value=False):
            with mock.patch("subprocess.run", return_value=result) as run:
                return engine.check(pid), run

    def test_a_sweep_asks_without_a_pid(self):
        _, run = self.run_check(completed([report()]))
        self.assertEqual(run.call_args[0][0], ["/opt/Ksnap", "-m", "Check"])

    def test_one_process_is_asked_about_by_pid(self):
        _, run = self.run_check(completed([report()]), pid=4321)
        self.assertEqual(
            run.call_args[0][0], ["/opt/Ksnap", "-m", "Check", "-p", "4321"]
        )

    def test_reports_come_back_keyed_by_pid(self):
        reports, _ = self.run_check(completed([report(pid=7), report(pid=9)]))
        self.assertEqual(sorted(reports), [7, 9])

    def test_exit_code_eleven_is_an_answer_not_a_failure(self):
        # the engine uses 11 for "this process is not dumpable"
        reports, _ = self.run_check(
            completed([report(pid=7, dumpable=False)], returncode=11)
        )
        self.assertFalse(reports[7]["dumpable"])

    def test_a_real_engine_failure_raises(self):
        with self.assertRaises(engine.EngineError):
            self.run_check(completed([], returncode=1, stderr="Mode not recognized"))

    def test_one_unreadable_line_does_not_cost_the_listing(self):
        result = completed([report(pid=7)])
        result.stdout = "{not json\n" + result.stdout
        reports, _ = self.run_check(result)

        self.assertEqual(list(reports), [7])
        entries, _ = engine.logbook.since(0)
        self.assertTrue(any("unreadable" in entry["message"] for entry in entries))

    def test_a_missing_engine_binary_raises(self):
        # _binary() already explains how to build it, the check just has to let
        # that through rather than listing every process as fine
        with mock.patch.object(
            engine, "_binary", side_effect=engine.EngineError("run 'make'")
        ):
            with self.assertRaises(engine.EngineError) as raised:
                engine.check()

        self.assertIn("make", str(raised.exception))


class VerdictTest(unittest.TestCase):
    """How one report collapses into ok, risky, blocked or unknown."""

    def test_a_clean_report_is_ok(self):
        verdict = eligibility.verdict_from_report(report())
        self.assertEqual(verdict["level"], eligibility.OK)
        self.assertEqual(verdict["reasons"], [])
        self.assertEqual(verdict["source"], "engine")

    def test_the_engine_reason_is_taken_as_it_is(self):
        verdict = eligibility.verdict_from_report(
            report(
                dumpable=False,
                reasons=[{"code": "multi_threaded", "detail": "it has 11"}],
            )
        )
        self.assertEqual(verdict["level"], eligibility.BLOCKED)
        self.assertEqual(verdict["reasons"][0]["code"], "multi_threaded")
        self.assertEqual(verdict["reasons"][0]["message"], "it has 11")

    def test_a_refusal_without_a_reason_still_blocks(self):
        verdict = eligibility.verdict_from_report(report(dumpable=False))
        self.assertEqual(verdict["level"], eligibility.BLOCKED)

    def test_a_missing_report_is_unknown(self):
        verdict = eligibility.verdict_from_report(None)
        self.assertEqual(verdict["level"], eligibility.UNKNOWN)
        self.assertEqual(verdict["reasons"][0]["code"], "not_checked")

    # ------------------------------------------- the layer the panel owns

    def test_arguments_are_risky(self):
        verdict = eligibility.verdict_from_report(report(argc=4))
        self.assertEqual(verdict["level"], eligibility.RISKY)
        self.assertEqual(verdict["reasons"][0]["code"], "arguments_not_restored")

    def test_open_descriptors_are_risky_and_counted(self):
        verdict = eligibility.verdict_from_report(report(open_fds=3, volatile_fds=2))
        message = verdict["reasons"][0]["message"]
        self.assertEqual(verdict["level"], eligibility.RISKY)
        self.assertIn("2 socket(s) or pipe(s)", message)
        self.assertIn("1 open file(s)", message)

    def test_children_are_risky(self):
        verdict = eligibility.verdict_from_report(report(children=2))
        self.assertEqual(verdict["reasons"][0]["code"], "has_children")

    def test_a_big_snapshot_is_risky(self):
        bytes_over = (config.MAX_SNAPSHOT_MB + 1) * 1024 * 1024
        verdict = eligibility.verdict_from_report(report(snapshot_bytes=bytes_over))
        self.assertEqual(verdict["reasons"][0]["code"], "large_snapshot")

    def test_a_snapshot_under_the_threshold_is_not_flagged(self):
        verdict = eligibility.verdict_from_report(report(snapshot_bytes=1024))
        self.assertEqual(verdict["level"], eligibility.OK)

    def test_a_space_in_the_executable_path_is_risky(self):
        verdict = eligibility.verdict_from_report(report(exe="/opt/my counter"))
        self.assertEqual(verdict["reasons"][0]["code"], "path_with_space")

    def test_blocked_reasons_come_before_risky_ones(self):
        verdict = eligibility.verdict_from_report(
            report(
                dumpable=False,
                reasons=[{"code": "shared_mapping", "detail": "one shared mapping"}],
                argc=3,
                children=1,
            )
        )
        levels = [reason["level"] for reason in verdict["reasons"]]
        self.assertEqual(verdict["level"], eligibility.BLOCKED)
        self.assertEqual(levels[0], eligibility.BLOCKED)
        self.assertEqual(len(levels), 3)


class ListingTest(unittest.TestCase):
    """verdicts_for(): joining the engine report onto the /proc rows."""

    def rows(self, *pids):
        return [{"pid": pid} for pid in pids]

    def test_verdicts_are_joined_by_pid(self):
        with mock.patch.object(
            engine, "check", return_value={7: report(pid=7, argc=5)}
        ):
            found = eligibility.verdicts_for(self.rows(7, 9))

        self.assertEqual(found[0]["eligibility"]["level"], eligibility.RISKY)
        # pid 9 was not in the report, the panel says so instead of guessing
        self.assertEqual(found[1]["eligibility"]["level"], eligibility.UNKNOWN)

    def test_without_an_engine_every_row_is_unknown(self):
        with mock.patch.object(
            engine, "check", side_effect=engine.EngineError("cannot start the engine")
        ):
            found = eligibility.verdicts_for(self.rows(7, 9))

        for process in found:
            self.assertEqual(process["eligibility"]["level"], eligibility.UNKNOWN)
            self.assertEqual(process["eligibility"]["source"], "unavailable")
            self.assertIn("cannot start", process["eligibility"]["reasons"][0]["message"])

    def test_counts_cover_every_level(self):
        found = [
            {"eligibility": {"level": "ok"}},
            {"eligibility": {"level": "risky"}},
            {"eligibility": {"level": "unknown"}},
        ]
        self.assertEqual(
            eligibility.count_levels(found),
            {"ok": 1, "risky": 1, "blocked": 0, "unknown": 1},
        )


class RequireDumpableTest(unittest.TestCase):
    """The gate in front of a dump."""

    def test_a_blocked_process_is_refused_with_the_engine_reason(self):
        blocked = report(
            pid=55,
            dumpable=False,
            reasons=[{"code": "ptrace_refused", "detail": "cannot seize it"}],
        )
        with mock.patch.object(engine, "check", return_value={55: blocked}):
            with self.assertRaises(processes.ProcessError) as caught:
                eligibility.require_dumpable(55)

        self.assertIn("cannot seize it", str(caught.exception))

    def test_an_unchecked_process_is_refused_too(self):
        with mock.patch.object(engine, "check", return_value={}):
            with self.assertRaises(processes.ProcessError):
                eligibility.require_dumpable(55)

    def test_a_risky_process_passes_and_keeps_its_caveats(self):
        with mock.patch.object(
            engine, "check", return_value={55: report(pid=55, children=1)}
        ):
            verdict = eligibility.require_dumpable(55)

        self.assertEqual(verdict["level"], eligibility.RISKY)
        self.assertEqual(eligibility.describe(verdict, eligibility.RISKY).__len__(), 1)

    def test_the_gate_asks_about_that_one_pid(self):
        with mock.patch.object(
            engine, "check", return_value={55: report(pid=55)}
        ) as check:
            eligibility.require_dumpable("55")

        check.assert_called_once_with(55)


if __name__ == "__main__":
    unittest.main()
