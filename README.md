# Suspicious Process Activity Detector

## Project Overview
A Python-based defensive security tool that analyses simulated Windows process records from CSV files and identifies potentially suspicious PowerShell command-line activity.

## Features
- Reads process records from CSV files.
- Detects encoded PowerShell commands.
- Identifies Execution Policy Bypass usage.
- Detects hidden PowerShell execution.
- Displays process ID, process name, and parent process.
- Supports different CSV input files.
- Handles missing-file errors.
- Provides a scan summary.

## Project Structure

```text
Suspicious_Process_Activity_Detector/
├── data/
│   ├── sample_processes.csv
│   └── normal_processes.csv
├── reports/
│   └── test_results.md
├── screenshots/
├── src/
│   └── process_detector.py
└── README.md
```

## Requirements
- Python 3.x
- No external Python libraries required.

## How to Run

Open PowerShell in the project directory.

Run the suspicious process dataset:

```powershell
python src\process_detector.py data\sample_processes.csv
```

Run the normal process dataset:

```powershell
python src\process_detector.py data\normal_processes.csv
```

## Detection Indicators

| Indicator | Description |
|---|---|
| `-EncodedCommand` | Detects encoded PowerShell commands |
| `-ExecutionPolicy Bypass` | Detects execution policy bypass usage |
| `-WindowStyle Hidden` | Detects hidden PowerShell execution |

## Testing
- Positive detection test: PASS
- Negative detection test: PASS
- Missing file handling: PASS

See `reports/test_results.md` for details.

## Skills Demonstrated
- Python programming
- CSV file processing
- Windows process analysis concepts
- PowerShell security monitoring concepts
- Basic detection engineering
- Error handling and testing

## Limitations
This project analyses simulated process records. It does not currently collect live Windows process telemetry.

Detected command-line indicators are investigation leads, not proof of malicious activity. Legitimate administrative activity may use similar commands.

## Future Improvements
- Live Windows process collection
- Parent-child process relationship analysis
- Alert severity and risk scoring
- JSON report generation

## Disclaimer
This project is developed for educational and defensive cybersecurity learning purposes.
