# File Integrity Monitor

A lightweight Python tool for monitoring file integrity using SHA-256 cryptographic hashes.

## Overview

The File Integrity Monitor is an educational cybersecurity project designed to detect changes in files within a monitored directory.

It creates a baseline containing the SHA-256 hash of each file. Subsequent integrity checks compare the current files against this baseline and identify files that have been added, modified, or deleted.

The project uses Python's standard library and does not require third-party packages.

## Features

- **SHA-256 hashing:** Calculates cryptographic hashes using Python's `hashlib`.
- **Baseline creation:** Records file paths and hashes in a JSON file.
- **Integrity monitoring:** Detects added, modified, and deleted files.
- **CSV reporting:** Exports results with expected and current hashes.
- **Input validation:** Rejects malformed baseline data, invalid hashes, and unsafe file paths.
- **Safe file creation:** Refuses to overwrite an existing baseline or report.
- **Command-line interface:** Configures paths through command-line arguments.
- **Automated tests:** Tests core functionality and important security checks.

## Requirements

- Python 3.10 or newer recommended.
- No third-party Python packages are required.

The project has been tested with Python 3.14.

## Project Structure

```text
file-integrity-monitor/
├── file_integrity_monitor.py
├── test_file_integrity_monitor.py
├── baseline.json
├── README.md
├── requirements.txt
├── .gitignore
├── reports/
│   └── integrity_report.csv
└── test_data/
    └── example.txt
```

## Getting Started

### 1. Open the project directory

In PowerShell:

```powershell
cd "$HOME\Desktop\file-integrity-monitor"
```

### 2. Check the Python installation

```powershell
python --version
```

### 3. Create a baseline

A baseline records the current state of the monitored files.

```powershell
python .\file_integrity_monitor.py --directory ".\test_data" --baseline ".\baseline.json" --create-baseline
```

The program refuses to overwrite an existing baseline. Choose a new baseline path if you want to create another one.

### 4. Check file integrity

```powershell
python .\file_integrity_monitor.py --directory ".\test_data" --baseline ".\baseline.json" --report ".\reports\integrity_report.csv"
```

The program compares the monitored files against the baseline and generates a CSV report.

The report path must not already exist.

## Command-Line Options

| Option | Description |
|---|---|
| `--directory` | Directory to monitor. Defaults to `test_data`. |
| `--baseline` | JSON baseline path. Defaults to `baseline.json`. |
| `--report` | Destination for the CSV report. Defaults to `reports/integrity_report.csv`. |
| `--create-baseline` | Creates a baseline instead of checking integrity. |

Use `--help` to display the available options:

```powershell
python .\file_integrity_monitor.py --help
```

## Understanding the Results

The integrity check reports three categories:

- **ADDED:** Files present in the monitored directory but absent from the baseline.
- **MODIFIED:** Files whose current SHA-256 hash differs from the baseline.
- **DELETED:** Files recorded in the baseline that are no longer present in the monitored directory.

The CSV report contains the following columns:

| Column | Description |
|---|---|
| `File` | Relative path of the file. |
| `Status` | Detected status: added, modified, or deleted. |
| `Expected SHA-256` | Hash recorded in the baseline, when available. |
| `Current SHA-256` | Hash calculated during the current check, when available. |

## Running the Tests

Run the automated test suite:

```powershell
python -m py_compile .\file_integrity_monitor.py .\test_file_integrity_monitor.py
python -m unittest -v test_file_integrity_monitor
```

The tests cover SHA-256 calculation, baseline handling, CSV export, and detection of added, modified, and deleted files. They also check invalid hashes, unsafe paths, absolute paths, and protection against baseline overwriting.

## Security Considerations

- **Protect the baseline:** An attacker who can modify both monitored files and the baseline may be able to conceal changes.
- **Use a trusted location:** Store the baseline and reports somewhere with appropriate access controls.
- **Understand the scope:** This tool detects changes relative to a baseline; it does not prevent file modification.
- **Review results:** Unexpected changes should be investigated rather than automatically assumed to be malicious.
- **No authenticity guarantee:** The JSON baseline is not digitally signed, so its authenticity is not independently verified.
- **Educational scope:** This project is not a replacement for a production endpoint detection or file integrity monitoring solution.

## Learning Objectives

This project demonstrates practical use of:

- Python file handling and `pathlib`
- SHA-256 hashing with `hashlib`
- JSON serialization and validation
- CSV report generation
- Command-line argument parsing with `argparse`
- Exception handling
- Unit testing with `unittest`
- Basic defensive cybersecurity principles

## Future Improvements

Possible enhancements include:

- Configurable exclusion patterns
- More detailed logging
- Improved handling of files that change during scanning
- Additional tests for filesystem errors and edge cases
- Optional digital signatures or authenticated baselines
- Integration into a scheduled monitoring workflow

## License

No license has been specified yet. Add a license before distributing or reusing the project publicly.
