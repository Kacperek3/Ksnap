import os
import tempfile
import unittest
from pathlib import Path

import context  # noqa: F401
from fakeproc import fake_proc

import processes


class ProcessListingTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.proc = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def test_reads_the_fields_the_panel_shows(self):
        fake_proc(self.proc, 1234, comm="counter", threads=1, rss_kb=4096)

        process = processes.read_process(1234, proc=self.proc)

        self.assertEqual(process["pid"], 1234)
        self.assertEqual(process["name"], "counter")
        self.assertEqual(process["threads"], 1)
        self.assertEqual(process["rss_kb"], 4096)
        self.assertEqual(process["state"], "sleeping")
        # the verdict is not this module's business any more, the engine owns it
        self.assertNotIn("eligibility", process)

    def test_a_command_with_spaces_in_comm_is_parsed(self):
        fake_proc(self.proc, 22, comm="my prog (x)")
        self.assertEqual(processes.read_process(22, proc=self.proc)["name"], "my prog (x)")

    def test_every_process_with_an_address_space_is_listed(self):
        # filtering by verdict happens in the HTTP layer, on engine output
        fake_proc(self.proc, 55, threads=8)
        fake_proc(self.proc, 56)
        found, _ = processes.list_processes(proc=self.proc)
        self.assertEqual([item["pid"] for item in found], [55, 56])
        self.assertEqual(found[0]["threads"], 8)

    def test_kernel_threads_are_skipped_and_counted(self):
        fake_proc(self.proc, 7, cmdline="")
        self.assertIsNone(processes.read_process(7, proc=self.proc))
        self.assertEqual(processes.list_processes(proc=self.proc), ([], 1))

    def test_missing_process_is_not_an_error(self):
        self.assertIsNone(processes.read_process(4242, proc=self.proc))

    def test_query_filters_on_pid_name_and_cmdline(self):
        fake_proc(self.proc, 100, comm="counter", cmdline="/bin/counter")
        fake_proc(self.proc, 200, comm="editor", cmdline="/usr/bin/editor file")

        listed = lambda query: [
            item["pid"] for item in processes.list_processes(query, proc=self.proc)[0]
        ]

        self.assertEqual(listed(None), [100, 200])
        self.assertEqual(listed("counter"), [100])
        self.assertEqual(listed("200"), [200])
        self.assertEqual(listed("usr/bin"), [200])
        self.assertEqual(listed("nothing"), [])


class PidValidationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.proc = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def test_accepts_a_live_pid(self):
        fake_proc(self.proc, 4321)
        self.assertEqual(processes.validate_pid("4321", proc=self.proc), 4321)

    def test_refuses_unusable_targets(self):
        for value in ["abc", None, 1, 0, -5, 9999]:
            with self.subTest(value=value):
                with self.assertRaises(processes.ProcessError):
                    processes.validate_pid(value, proc=self.proc)

    def test_refuses_the_api_itself(self):
        fake_proc(self.proc, os.getpid())
        with self.assertRaises(processes.ProcessError):
            processes.validate_pid(os.getpid(), proc=self.proc)


if __name__ == "__main__":
    unittest.main()
