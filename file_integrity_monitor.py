
import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PurePosixPath


def calculate_sha256(file_path: Path) -> str:
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while True:
            chunk = file.read(4096)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()


def create_baseline(directory: Path, baseline_path: Path) -> dict:
    """Create a JSON baseline containing file hashes."""
    if not directory.exists():
        raise FileNotFoundError(f"Directory does not exist: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    files = {}

    for file_path in sorted(directory.rglob("*")):
        if file_path.is_symlink() or not file_path.is_file():
            continue

        relative_path = file_path.relative_to(directory).as_posix()
        files[relative_path] = {
            "sha256": calculate_sha256(file_path)
        }

    baseline = {
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": files,
    }

    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    with baseline_path.open("x", encoding="utf-8") as file:
        json.dump(baseline, file, indent=4, ensure_ascii=False)

    return baseline



def load_baseline(baseline_path: Path) -> dict:
    """Load and validate a JSON baseline."""
    with baseline_path.open("r", encoding="utf-8") as file:
        baseline = json.load(file)

    if not isinstance(baseline, dict):
        raise ValueError("Baseline must be a JSON object.")

    if type(baseline.get("version")) is not int or baseline["version"] != 1:
        raise ValueError("Unsupported baseline version.")

    if not isinstance(baseline.get("created_at"), str):
        raise ValueError("Invalid baseline creation date.")

    files = baseline.get("files")
    if not isinstance(files, dict):
        raise ValueError("Baseline files must be a JSON object.")

    for relative_path, metadata in files.items():
        if not isinstance(relative_path, str) or not relative_path:
            raise ValueError("Invalid file path in baseline.")

        # Baseline paths must be normalized relative POSIX paths.
        path = PurePosixPath(relative_path)

        if (
            path.is_absolute()
            or "\\" in relative_path
            or ":" in relative_path
            or any(part in ("", ".", "..") for part in relative_path.split("/"))
        ):
            raise ValueError(f"Unsafe file path in baseline: {relative_path}")

        if not isinstance(metadata, dict):
            raise ValueError(f"Invalid metadata for {relative_path}.")

        fingerprint = metadata.get("sha256")
        if (
            not isinstance(fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        ):
            raise ValueError(f"Invalid SHA-256 for {relative_path}.")

    return baseline



def check_integrity(directory: Path, baseline: dict) -> dict:
    """Compare current files with the saved baseline."""
    if not directory.exists():
        raise FileNotFoundError(f"Directory does not exist: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    current_hashes = {}

    for file_path in sorted(directory.rglob("*")):
        if file_path.is_symlink() or not file_path.is_file():
            continue

        relative_path = file_path.relative_to(directory).as_posix()
        current_hashes[relative_path] = calculate_sha256(file_path)

    baseline_files = baseline["files"]

    added = sorted(set(current_hashes) - set(baseline_files))
    deleted = sorted(set(baseline_files) - set(current_hashes))
    modified = sorted(
        path
        for path in set(current_hashes) & set(baseline_files)
        if current_hashes[path] != baseline_files[path]["sha256"]
    )

    return {
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "current_hashes": current_hashes,
    }


def export_csv(
    results: dict,
    baseline: dict,
    current_hashes: dict,
    report_path: Path,
) -> None:
    """Export integrity check results to a new CSV report."""
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with report_path.open("x", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        writer.writerow([
            "File",
            "Status",
            "Expected SHA-256",
            "Current SHA-256",
        ])

        for status in ("added", "modified", "deleted"):
            for relative_path in results[status]:
                expected_hash = (
                    baseline["files"]
                    .get(relative_path, {})
                    .get("sha256", "")
                )
                current_hash = current_hashes.get(relative_path, "")

                writer.writerow([
                    relative_path,
                    status.upper(),
                    expected_hash,
                    current_hash,
                ])


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Monitor file integrity using SHA-256 hashes."
    )

    parser.add_argument(
        "--directory",
        type=Path,
        default=Path("test_data"),
        help="Directory to monitor (default: test_data).",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("baseline.json"),
        help="Path to the JSON baseline (default: baseline.json).",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("reports/integrity_report.csv"),
        help="Path for the new CSV report.",
    )
    parser.add_argument(
        "--create-baseline",
        action="store_true",
        help="Create a baseline instead of checking integrity.",
    )

    return parser


def main() -> int:
    """Run the requested command."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.create_baseline:
            baseline = create_baseline(args.directory, args.baseline)
            print(f"Baseline created: {args.baseline}")
            print(f"Files recorded: {len(baseline['files'])}")
            return 0

        baseline = load_baseline(args.baseline)
        results = check_integrity(args.directory, baseline)

        export_csv(
            results,
            baseline,
            results["current_hashes"],
            args.report,
        )

        print("Integrity check completed.")

        for category in ("added", "modified", "deleted"):
            files = results[category]
            print(f"\n{category.upper()}: {len(files)}")
            for relative_path in files:
                print(f"  - {relative_path}")

        if not any(
            results[key] for key in ("added", "modified", "deleted")
        ):
            print("\nNo changes detected.")

        print(f"\nCSV report created: {args.report}")
        return 0

    except FileExistsError as error:
        print(
            f"Error: file already exists; nothing was overwritten: {error.filename or error}",
            file=sys.stderr,
        )
        return 1
    except FileNotFoundError as error:
        missing_path = error.filename or "requested path"
        print(f"Error: file or directory not found: {missing_path}", file=sys.stderr)
        return 1
    except PermissionError as error:
        target = error.filename or "requested path"
        print(f"Error: permission denied: {target}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

