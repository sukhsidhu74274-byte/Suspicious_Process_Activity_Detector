# Test Results - Suspicious Process Activity Detector

## 1. Project Overview
The Suspicious Process Activity Detector is a Python-based defensive tool that analyses simulated Windows process records from CSV files.

It identifies potentially suspicious PowerShell command-line indicators.

## 2. Test Cases

### Test 1: Positive Detection Test
- Input: `sample_processes.csv`
- Total processes: 7
- Flagged processes: 2
- Total findings: 3
- Result: PASS

Detected indicators:
- Execution Policy Bypass
- Encoded PowerShell Command
- Hidden PowerShell Execution

### Test 2: Negative Detection Test
- Input: `normal_processes.csv`
- Total processes: 5
- Flagged processes: 0
- Total findings: 0
- Result: PASS

No suspicious indicators were detected.

### Test 3: Missing File Test
- Input: `data/missing.csv`
- Expected result: Display a file-not-found error.
- Observed result: Error displayed correctly.
- Result: PASS

## 3. Final Test Summary

| Test | Result |
|---|---|
| Positive Detection | PASS |
| Negative Detection | PASS |
| Missing File Handling | PASS |

**Overall Status: ALL 3 TESTS PASSED**

## 4. Limitations
- Uses simulated process records.
- Does not collect live Windows process telemetry.
- Detection relies on predefined command-line patterns.
- Suspicious indicators do not confirm malicious activity.

## 5. Future Improvements
- Live Windows process collection.
- Parent-child process analysis.
- Risk scoring and alert severity.
- JSON and CSV report generation.

## 6. Conclusion
The project successfully demonstrates basic process activity analysis, suspicious PowerShell indicator detection, and error handling using Python.