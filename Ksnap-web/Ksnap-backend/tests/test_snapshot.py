import struct
import tempfile
import unittest
from pathlib import Path

import context  # noqa: F401  (import path setup)

import snapshot


def build_snapshot(exe_path="/bin/counter", vma_count=7, version=snapshot.FORMAT_VERSION,
                   magic=snapshot.MAGIC):
    """A header identical to the one the engine writes, plus a fake payload."""
    regs = [0] * snapshot._REGS_COUNT
    regs[snapshot._RIP] = 0x401136
    regs[snapshot._RSP] = 0x7FFD1234

    kernel_maps = []
    for index in range(snapshot.MAX_KERNEL_MAPS):
        if index == 0:
            kernel_maps += [0x7FFFF7FC0000, 8192, b"[vdso]"]
        else:
            kernel_maps += [0, 0, b""]

    return struct.pack(
        snapshot.HEADER_FORMAT,
        magic,
        version,
        vma_count,
        snapshot.HEADER_SIZE,
        snapshot.HEADER_SIZE + vma_count * 48,
        0,
        snapshot.HEADER_SIZE + vma_count * 48,
        len(exe_path),
        exe_path.encode(),
        1,
        *kernel_maps,
        *regs,
    ) + b"\x00" * 128


class HeaderLayoutTest(unittest.TestCase):
    def test_header_size_matches_the_engine(self):
        # dump_format.h: sizeof(ksnap_dump_header_t) on x86_64
        self.assertEqual(snapshot.HEADER_SIZE, 4560)


class ReadHeaderTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def write(self, name, data):
        path = self.path / name
        path.write_bytes(data)
        return path

    def test_reads_every_field_shown_in_the_panel(self):
        header = snapshot.read_header(self.write("a.ksnap", build_snapshot()))

        self.assertEqual(header["exe_path"], "/bin/counter")
        self.assertEqual(header["vma_count"], 7)
        self.assertEqual(header["version"], snapshot.FORMAT_VERSION)
        self.assertEqual(header["rip"], "0x401136")
        self.assertEqual(header["rsp"], "0x7ffd1234")
        self.assertEqual(header["kernel_maps"], [
            {"name": "[vdso]", "start_address": "0x7ffff7fc0000", "size": 8192}
        ])

    def test_rejects_a_foreign_file(self):
        path = self.write("b.ksnap", build_snapshot(magic=b"NOTKSNAP"))
        with self.assertRaises(snapshot.SnapshotError):
            snapshot.read_header(path)

    def test_rejects_another_format_version(self):
        path = self.write("c.ksnap", build_snapshot(version=99))
        with self.assertRaises(snapshot.SnapshotError):
            snapshot.read_header(path)

    def test_rejects_a_truncated_file(self):
        path = self.write("d.ksnap", build_snapshot()[:100])
        with self.assertRaises(snapshot.SnapshotError):
            snapshot.read_header(path)

    def test_listing_reports_broken_files_instead_of_hiding_them(self):
        self.write("good.ksnap", build_snapshot())
        self.write("broken.ksnap", b"garbage")
        self.write("ignored.txt", b"garbage")

        listed = {item["name"]: item for item in snapshot.list_snapshots(self.path)}

        self.assertEqual(set(listed), {"good.ksnap", "broken.ksnap"})
        self.assertNotIn("error", listed["good.ksnap"])
        self.assertIn("error", listed["broken.ksnap"])

    def test_delete_removes_the_file(self):
        self.write("gone.ksnap", build_snapshot())
        snapshot.delete(self.path, "gone.ksnap")
        self.assertFalse((self.path / "gone.ksnap").exists())


class NameValidationTest(unittest.TestCase):
    def test_appends_the_suffix(self):
        self.assertEqual(snapshot.validate_name("counter-42"), "counter-42.ksnap")
        self.assertEqual(snapshot.validate_name("counter.ksnap"), "counter.ksnap")

    def test_refuses_anything_that_could_leave_the_directory(self):
        for name in ["../evil", "dir/name", "/etc/passwd", "", "  ", "a" * 80, None, 5]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    snapshot.validate_name(name)

    def test_resolve_stays_inside_the_snapshot_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            resolved = snapshot.resolve(directory, "ok")
            self.assertEqual(resolved.parent, Path(directory).resolve())


if __name__ == "__main__":
    unittest.main()
