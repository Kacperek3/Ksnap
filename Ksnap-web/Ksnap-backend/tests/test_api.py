import tempfile
import unittest
from pathlib import Path
from unittest import mock

import context  # noqa: F401
from fakeproc import fake_proc
from test_check import report

import app as app_module
import config
import directories
import eligibility
import engine
import processes
from test_snapshot import build_snapshot


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.snapshots = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

        patched = mock.patch.object(config, "SNAPSHOT_DIR", self.snapshots)
        patched.start()
        self.addCleanup(patched.stop)

        # the folder registry lives next to the store, never in the real one
        patched_registry = mock.patch.object(
            config, "DIRECTORIES_FILE", self.snapshots / "directories.json"
        )
        patched_registry.start()
        self.addCleanup(patched_registry.stop)

        # a second folder a dump can be pointed at
        self.other_directory = tempfile.TemporaryDirectory()
        self.other = Path(self.other_directory.name).resolve()
        self.addCleanup(self.other_directory.cleanup)

        # a fake /proc for the display fields, plus canned engine reports for
        # the verdicts: one process per level
        self.proc_directory = tempfile.TemporaryDirectory()
        self.proc = Path(self.proc_directory.name)
        self.addCleanup(self.proc_directory.cleanup)
        fake_proc(self.proc, 4321, comm="counter")
        fake_proc(self.proc, 4322, comm="browser", threads=16)
        fake_proc(self.proc, 4323, comm="server", cmdline="/bin/server --port 80")

        patched_proc = mock.patch.object(processes, "PROC", self.proc)
        patched_proc.start()
        self.addCleanup(patched_proc.stop)

        self.reports = {
            4321: report(pid=4321),
            4322: report(
                pid=4322,
                dumpable=False,
                reasons=[{"code": "multi_threaded", "detail": "it has 16 threads"}],
            ),
            4323: report(pid=4323, argc=3),
        }
        patched_check = mock.patch.object(
            engine, "check", side_effect=self.fake_check
        )
        patched_check.start()
        self.addCleanup(patched_check.stop)

        engine.logbook.clear()
        self.client = app_module.create_app().test_client()

    def fake_check(self, pid=None):
        """Stand in for the engine: all reports, or the one that was asked for."""
        if pid is None:
            return dict(self.reports)
        return (
            {int(pid): self.reports[int(pid)]} if int(pid) in self.reports else {}
        )

    def write_snapshot(self, name="counter.ksnap"):
        (self.snapshots / name).write_bytes(build_snapshot())
        return name

    # ---------------------------------------------------------------- status

    def test_status_describes_the_engine_and_the_session(self):
        payload = self.client.get("/api/status").get_json()

        self.assertIn("engine_present", payload)
        self.assertIn("sudo", payload)
        self.assertEqual(payload["snapshot_dir"], str(self.snapshots))

    def test_process_listing_has_the_expected_shape(self):
        payload = self.client.get("/api/processes").get_json()

        self.assertIsInstance(payload["processes"], list)
        self.assertEqual(
            payload["counts"], {"ok": 1, "risky": 1, "blocked": 1, "unknown": 0}
        )
        self.assertIn("kernel_threads", payload)

    def test_process_listing_hides_the_processes_the_engine_cannot_restore(self):
        payload = self.client.get("/api/processes").get_json()

        self.assertEqual([item["pid"] for item in payload["processes"]], [4321, 4323])

    def test_show_all_brings_the_rejected_processes_back_with_a_reason(self):
        payload = self.client.get("/api/processes?all=1").get_json()
        listed = {item["pid"]: item["eligibility"] for item in payload["processes"]}

        self.assertEqual(sorted(listed), [4321, 4322, 4323])
        self.assertEqual(listed[4322]["level"], eligibility.BLOCKED)
        self.assertEqual(listed[4322]["reasons"][0]["code"], "multi_threaded")
        self.assertEqual(listed[4322]["source"], "engine")

    def test_process_listing_still_filters_by_query(self):
        payload = self.client.get("/api/processes?query=counter").get_json()

        self.assertEqual([item["pid"] for item in payload["processes"]], [4321])

    # ------------------------------------------------------------- snapshots

    def test_snapshot_listing_parses_the_store(self):
        self.write_snapshot()

        payload = self.client.get("/api/snapshots").get_json()

        self.assertEqual(payload["directory"], str(self.snapshots))
        self.assertEqual(payload["snapshots"][0]["name"], "counter.ksnap")
        self.assertEqual(payload["snapshots"][0]["exe_path"], "/bin/counter")

    def test_delete_removes_the_snapshot(self):
        self.write_snapshot("old.ksnap")

        response = self.client.delete("/api/snapshots/old.ksnap")

        self.assertEqual(response.status_code, 200)
        self.assertFalse((self.snapshots / "old.ksnap").exists())

    def test_delete_of_a_missing_snapshot_is_a_404(self):
        self.assertEqual(self.client.delete("/api/snapshots/ghost.ksnap").status_code, 404)

    def test_delete_cannot_reach_outside_the_store(self):
        response = self.client.delete("/api/snapshots/..%2F..%2Fpasswd")

        self.assertIn(response.status_code, (400, 404))

    # ------------------------------------------------------------------ dump

    def test_dump_passes_the_validated_pid_and_name_to_the_engine(self):
        with mock.patch.object(engine, "dump", return_value={"name": "x.ksnap"}) as dump:
            response = self.client.post(
                "/api/dump", json={"pid": 4321, "name": "counter-4321"}
            )

        self.assertEqual(response.status_code, 200)
        dump.assert_called_once_with(4321, "counter-4321", kill=False, directory=None)
        self.assertFalse(response.get_json()["killed"])

    def test_dump_can_end_the_process(self):
        with mock.patch.object(engine, "dump", return_value={"name": "x.ksnap"}) as dump:
            response = self.client.post(
                "/api/dump", json={"pid": 4321, "name": "counter-4321", "kill": True}
            )

        self.assertEqual(response.status_code, 200)
        dump.assert_called_once_with(4321, "counter-4321", kill=True, directory=None)
        self.assertTrue(response.get_json()["killed"])

    def test_dump_refuses_a_kill_flag_that_is_not_a_boolean(self):
        with mock.patch.object(engine, "dump") as dump:
            response = self.client.post(
                "/api/dump", json={"pid": 4321, "kill": "yes"}
            )

        self.assertEqual(response.status_code, 400)
        dump.assert_not_called()

    def test_dump_refuses_a_process_the_engine_cannot_restore(self):
        with mock.patch.object(engine, "dump") as dump:
            response = self.client.post("/api/dump", json={"pid": 4322})

        self.assertEqual(response.status_code, 400)
        self.assertIn("16 threads", response.get_json()["error"])
        dump.assert_not_called()

    def test_dump_of_a_risky_process_records_the_caveats(self):
        with mock.patch.object(engine, "dump", return_value={"name": "x.ksnap"}):
            response = self.client.post("/api/dump", json={"pid": 4323})

        self.assertEqual(response.status_code, 200)
        entries, _ = engine.logbook.since(0)
        caveats = [entry for entry in entries if entry["source"] == "eligibility"]
        self.assertTrue(caveats)
        self.assertIn("arguments", caveats[0]["message"])

    def test_dump_rejects_an_unusable_pid(self):
        response = self.client.post("/api/dump", json={"pid": "not a pid"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_a_listing_without_an_engine_is_unknown_not_a_guess(self):
        with mock.patch.object(
            engine, "check", side_effect=engine.EngineError("run 'make'")
        ):
            payload = self.client.get("/api/processes?all=1").get_json()

        self.assertEqual(payload["counts"]["unknown"], 3)
        for process in payload["processes"]:
            self.assertEqual(process["eligibility"]["source"], "unavailable")

    def test_dump_is_refused_when_the_engine_cannot_be_asked(self):
        with mock.patch.object(engine, "dump") as dump:
            with mock.patch.object(
                engine, "check", side_effect=engine.EngineError("run 'make'")
            ):
                response = self.client.post("/api/dump", json={"pid": 4321})

        self.assertEqual(response.status_code, 409)
        dump.assert_not_called()

    def test_dump_reports_an_engine_failure_without_a_crash(self):
        with mock.patch.object(
            engine, "dump", side_effect=engine.EngineError("cannot seize process")
        ):
            response = self.client.post("/api/dump", json={"pid": 4321})

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "cannot seize process")

    # --------------------------------------------------------------- restore

    def test_restore_needs_a_snapshot_name(self):
        self.assertEqual(self.client.post("/api/restore", json={}).status_code, 400)

    def test_restore_refuses_a_name_that_escapes_the_store(self):
        response = self.client.post("/api/restore", json={"name": "../../etc/passwd"})

        self.assertEqual(response.status_code, 400)

    def test_restore_starts_a_session(self):
        session = {"snapshot": "counter.ksnap", "running": True}
        with mock.patch.object(engine, "restore", return_value=session) as restore:
            response = self.client.post("/api/restore", json={"name": "counter.ksnap"})

        restore.assert_called_once_with(
            "counter.ksnap", directory=self.snapshots.resolve()
        )
        self.assertEqual(response.get_json()["restore"], session)

    # --------------------------------------------------------------- folders

    def test_dump_into_another_folder_creates_it(self):
        target = self.other / "nested" / "store"
        with mock.patch.object(engine, "dump", return_value={"name": "x.ksnap"}) as dump:
            response = self.client.post(
                "/api/dump", json={"pid": 4321, "directory": str(target)}
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(target.is_dir())
        self.assertEqual(dump.call_args.kwargs["directory"], target)

    def test_dump_refuses_a_relative_folder(self):
        with mock.patch.object(engine, "dump") as dump:
            response = self.client.post(
                "/api/dump", json={"pid": 4321, "directory": "snapshots/here"}
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("absolute", response.get_json()["error"])
        dump.assert_not_called()

    def test_listing_covers_every_remembered_folder(self):
        self.write_snapshot("home.ksnap")
        (self.other / "away.ksnap").write_bytes(build_snapshot())
        directories.remember(self.other)

        payload = self.client.get("/api/snapshots").get_json()

        found = {item["name"]: item["directory"] for item in payload["snapshots"]}
        self.assertEqual(found["home.ksnap"], str(self.snapshots.resolve()))
        self.assertEqual(found["away.ksnap"], str(self.other))
        self.assertEqual(
            payload["directories"], [str(self.snapshots.resolve()), str(self.other)]
        )

    def test_restore_and_delete_refuse_a_folder_the_panel_never_wrote_to(self):
        (self.other / "away.ksnap").write_bytes(build_snapshot())

        with mock.patch.object(engine, "restore") as restore:
            response = self.client.post(
                "/api/restore",
                json={"name": "away.ksnap", "directory": str(self.other)},
            )
        self.assertEqual(response.status_code, 400)
        restore.assert_not_called()

        response = self.client.delete(
            "/api/snapshots/away.ksnap", query_string={"directory": str(self.other)}
        )
        self.assertEqual(response.status_code, 400)
        self.assertTrue((self.other / "away.ksnap").exists())

    def test_delete_works_in_a_remembered_folder(self):
        (self.other / "away.ksnap").write_bytes(build_snapshot())
        directories.remember(self.other)

        response = self.client.delete(
            "/api/snapshots/away.ksnap", query_string={"directory": str(self.other)}
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse((self.other / "away.ksnap").exists())

    def test_stop_without_a_session_is_reported_as_a_conflict(self):
        self.assertEqual(self.client.post("/api/restore/stop").status_code, 409)

    # ---------------------------------------------------------------- logs

    def test_logs_are_returned_incrementally(self):
        engine.logbook.append("first")
        engine.logbook.append("second")

        everything = self.client.get("/api/logs?since=0").get_json()
        self.assertEqual(
            [entry["message"] for entry in everything["entries"]], ["first", "second"]
        )

        rest = self.client.get("/api/logs?since=%d" % everything["cursor"]).get_json()
        self.assertEqual(rest["entries"], [])

        engine.logbook.append("third")
        rest = self.client.get("/api/logs?since=%d" % everything["cursor"]).get_json()
        self.assertEqual([entry["message"] for entry in rest["entries"]], ["third"])

    def test_a_non_numeric_cursor_is_a_400(self):
        self.assertEqual(self.client.get("/api/logs?since=abc").status_code, 400)

    def test_logs_can_be_cleared(self):
        engine.logbook.append("noise")
        self.client.delete("/api/logs")

        self.assertEqual(self.client.get("/api/logs?since=0").get_json()["entries"], [])


class EngineCommandTest(unittest.TestCase):
    """The engine call itself: right flags, no shell, sudo only when needed."""

    def test_dump_builds_the_expected_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(config, "SNAPSHOT_DIR", Path(directory)), \
                 mock.patch.object(engine, "_binary", return_value="/opt/Ksnap"), \
                 mock.patch.object(config, "uses_sudo", return_value=False), \
                 mock.patch("subprocess.run") as run, \
                 mock.patch("snapshot.read_header", return_value={"name": "a.ksnap"}):
                run.return_value = mock.Mock(returncode=0, stdout="", stderr="")

                engine.dump(1234, "a")

        argv = run.call_args[0][0]
        self.assertEqual(
            argv,
            ["/opt/Ksnap", "-m", "Dump", "-p", "1234", "-d", directory, "-n", "a.ksnap"],
        )
        self.assertNotIn("shell", run.call_args[1])

    def test_dump_with_kill_passes_k_to_the_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(config, "SNAPSHOT_DIR", Path(directory)), \
                 mock.patch.object(engine, "_binary", return_value="/opt/Ksnap"), \
                 mock.patch.object(config, "uses_sudo", return_value=False), \
                 mock.patch("subprocess.run") as run, \
                 mock.patch("snapshot.read_header", return_value={"name": "a.ksnap"}):
                run.return_value = mock.Mock(returncode=0, stdout="", stderr="")

                engine.dump(1234, "a", kill=True)

        self.assertEqual(run.call_args[0][0][-1], "-k")

    def test_dump_into_another_folder_passes_it_as_d_and_remembers_it(self):
        with tempfile.TemporaryDirectory() as store, \
             tempfile.TemporaryDirectory() as other:
            registry = Path(store) / "directories.json"
            with mock.patch.object(config, "SNAPSHOT_DIR", Path(store)), \
                 mock.patch.object(config, "DIRECTORIES_FILE", registry), \
                 mock.patch.object(engine, "_binary", return_value="/opt/Ksnap"), \
                 mock.patch.object(config, "uses_sudo", return_value=False), \
                 mock.patch("subprocess.run") as run, \
                 mock.patch("snapshot.read_header", return_value={"name": "a.ksnap"}):
                run.return_value = mock.Mock(returncode=0, stdout="", stderr="")

                header = engine.dump(1234, "a", directory=Path(other))
                remembered = directories.known()

            argv = run.call_args[0][0]
            self.assertEqual(argv[argv.index("-d") + 1], other)
            self.assertEqual(header["directory"], other)
            self.assertIn(Path(other).resolve(), remembered)

    def test_dump_is_prefixed_with_sudo_when_the_api_is_not_root(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(config, "SNAPSHOT_DIR", Path(directory)), \
                 mock.patch.object(engine, "_binary", return_value="/opt/Ksnap"), \
                 mock.patch.object(config, "uses_sudo", return_value=True), \
                 mock.patch("subprocess.run") as run, \
                 mock.patch("snapshot.read_header", return_value={}):
                run.return_value = mock.Mock(returncode=0, stdout="", stderr="")

                engine.dump(1234, "a")

        self.assertEqual(run.call_args[0][0][:2], [engine.SUDO, "-n"])

    def test_a_sudo_password_prompt_is_explained(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(config, "SNAPSHOT_DIR", Path(directory)), \
                 mock.patch.object(engine, "_binary", return_value="/opt/Ksnap"), \
                 mock.patch.object(config, "uses_sudo", return_value=True), \
                 mock.patch("subprocess.run") as run:
                run.return_value = mock.Mock(
                    returncode=1, stdout="", stderr="sudo: a password is required"
                )

                with self.assertRaises(engine.EngineError) as raised:
                    engine.dump(1234, "a")

        self.assertIn("NOPASSWD", str(raised.exception))

    def test_a_missing_binary_is_reported_clearly(self):
        with mock.patch.object(config, "ENGINE_BINARY", Path("/nowhere/Ksnap")):
            with self.assertRaises(engine.EngineError) as raised:
                engine.dump(1234, "a")

        self.assertIn("make", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
