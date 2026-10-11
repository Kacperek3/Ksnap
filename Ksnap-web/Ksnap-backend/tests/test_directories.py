import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import context  # noqa: F401  (import path setup)

import config
import directories


class DirectoriesTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.store = self.root / "store"
        self.store.mkdir()
        self.registry = self.store / "directories.json"

        for name, value in (("SNAPSHOT_DIR", self.store),
                            ("DIRECTORIES_FILE", self.registry)):
            patched = mock.patch.object(config, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def test_validate_creates_a_missing_folder(self):
        target = self.root / "a" / "b"

        self.assertEqual(directories.validate(str(target)), target)
        self.assertTrue(target.is_dir())

    def test_validate_refuses_what_the_engine_cannot_take(self):
        for bad in ("", "relative/path", "/tmp/with\x00nul", "/" + "x" * 5000, 42):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    directories.validate(bad)

    def test_validate_refuses_a_file(self):
        target = self.root / "file"
        target.write_text("")

        with self.assertRaises(ValueError):
            directories.validate(str(target))

    def test_the_default_store_is_always_known_first(self):
        self.assertEqual(directories.known(), [self.store])

    def test_remember_persists_and_does_not_duplicate(self):
        other = self.root / "other"
        other.mkdir()

        self.assertTrue(directories.remember(other))
        self.assertTrue(directories.remember(other))
        self.assertTrue(directories.remember(self.store))

        self.assertEqual(directories.known(), [self.store, other])
        self.assertEqual(json.loads(self.registry.read_text()), [str(other)])

    def test_a_removed_folder_is_no_longer_listed(self):
        other = self.root / "other"
        other.mkdir()
        directories.remember(other)
        other.rmdir()

        self.assertEqual(directories.known(), [self.store])

    def test_a_damaged_registry_falls_back_to_the_default_store(self):
        for content in ("not json", '{"a": 1}', "[1, 2]"):
            with self.subTest(content=content):
                self.registry.write_text(content)
                self.assertEqual(directories.known(), [self.store])

    def test_require_known_defaults_and_refuses_strangers(self):
        self.assertEqual(directories.require_known(None), self.store)
        self.assertEqual(directories.require_known(""), self.store)
        with self.assertRaises(ValueError):
            directories.require_known(str(self.root))


if __name__ == "__main__":
    unittest.main()
