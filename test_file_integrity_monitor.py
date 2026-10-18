import csv
import json
import tempfile
import unittest
from pathlib import Path

from file_integrity_monitor import (
    calculate_sha256,
    create_baseline,
    load_baseline,
    check_integrity,
    export_csv,
)


class TestFileIntegrityMonitor(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.directory = self.root / "test_data"
        self.directory.mkdir()
        self.baseline_path = self.root / "baseline.json"
        self.report_path = self.root / "reports" / "report.csv"
        self.file = self.directory / "example.txt"
        self.file.write_text("Bonjour", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_sha256(self):
        expected = (
            "9172e8eec99f144f72eca9a568759580"
            "edadb2cfd154857f07e657569493bc44"
        )
        self.assertEqual(calculate_sha256(self.file), expected)

    def test_create_and_load_baseline(self):
        baseline = create_baseline(self.directory, self.baseline_path)
        loaded = load_baseline(self.baseline_path)
        self.assertEqual(
            loaded["files"]["example.txt"]["sha256"],
            baseline["files"]["example.txt"]["sha256"],
        )

    def test_no_changes(self):
        baseline = create_baseline(self.directory, self.baseline_path)
        result = check_integrity(self.directory, baseline)
        self.assertEqual(result["added"], [])
        self.assertEqual(result["modified"], [])
        self.assertEqual(result["deleted"], [])

    def test_modified_file(self):
        baseline = create_baseline(self.directory, self.baseline_path)
        self.file.write_text("Modifie", encoding="utf-8")
        result = check_integrity(self.directory, baseline)
        self.assertEqual(result["modified"], ["example.txt"])

    def test_added_file(self):
        baseline = create_baseline(self.directory, self.baseline_path)
        (self.directory / "nouveau.txt").write_text(
            "Nouveau", encoding="utf-8"
        )
        result = check_integrity(self.directory, baseline)
        self.assertEqual(result["added"], ["nouveau.txt"])

    def test_deleted_file(self):
        baseline = create_baseline(self.directory, self.baseline_path)
        self.file.unlink()
        result = check_integrity(self.directory, baseline)
        self.assertEqual(result["deleted"], ["example.txt"])

    def test_csv_export(self):
        baseline = create_baseline(self.directory, self.baseline_path)
        self.file.write_text("Modifie", encoding="utf-8")
        result = check_integrity(self.directory, baseline)

        export_csv(
            result, baseline, result["current_hashes"], self.report_path
        )

        with self.report_path.open(
            "r", newline="", encoding="utf-8-sig"
        ) as file:
            rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Status"], "MODIFIED")

    def test_baseline_not_overwritten(self):
        create_baseline(self.directory, self.baseline_path)
        with self.assertRaises(FileExistsError):
            create_baseline(self.directory, self.baseline_path)

    def test_invalid_hash_rejected(self):
        self.baseline_path.write_text(
            json.dumps({
                "version": 1,
                "created_at": "test",
                "files": {
                    "example.txt": {"sha256": "invalid"}
                },
            }),
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            load_baseline(self.baseline_path)

    def test_unsafe_path_rejected(self):
        """Reject paths that attempt to escape the monitored directory."""
        import json
        import tempfile
        from pathlib import Path
        from file_integrity_monitor import load_baseline

        with tempfile.TemporaryDirectory() as temp_dir:
            baseline_path = Path(temp_dir) / "baseline.json"

            baseline = {
                "version": 1,
                "created_at": "2026-10-18T12:00:00+00:00",
                "files": {
                    "../secret.txt": {
                        "sha256": "a" * 64
                    }
                }
            }

            baseline_path.write_text(
                json.dumps(baseline),
                encoding="utf-8"
            )

            with self.assertRaises(ValueError):
                load_baseline(baseline_path)

    def test_absolute_path_rejected(self):
        """Reject absolute paths in the baseline."""
        with tempfile.TemporaryDirectory() as temp_dir:
            baseline_path = Path(temp_dir) / "baseline.json"

            baseline = {
                "version": 1,
                "created_at": "2026-10-18T12:00:00+00:00",
                "files": {
                    "C:/Windows/example.txt": {
                        "sha256": "a" * 64
                    }
                }
            }

            baseline_path.write_text(
                json.dumps(baseline),
                encoding="utf-8"
            )

            with self.assertRaises(ValueError):
                load_baseline(baseline_path)
if __name__ == "__main__":
    unittest.main(verbosity=2)

