import csv
import sys

# Get CSV file path from command line
if len(sys.argv) != 2:
    print("Usage: python src/process_detector.py <csv_file>")
    sys.exit(1)

file_path = sys.argv[1]

# Load process records
try:
    with open(file_path, "r") as file:
        reader = csv.DictReader(file)
        processes = list(reader)

except FileNotFoundError:
    print("[ERROR] File not found:", file_path)
    sys.exit(1)

# Define suspicious indicators
indicators = {
    "-encodedcommand": "Encoded PowerShell command detected",
    "-executionpolicy bypass": "Execution policy bypass detected",
    "-windowstyle hidden": "Hidden PowerShell execution detected"
}

# Analyse processes
alert_count = 0

for process in processes:
    command_line = process["CommandLine"].lower()
    findings = []

    for pattern, description in indicators.items():
        if pattern in command_line:
            findings.append(description)

    if findings:
        alert_count += 1

        print("\n[ALERT] Suspicious Process Activity")
        print("PID:", process["ProcessID"])
        print("Process:", process["ProcessName"])
        print("Parent:", process["ParentProcess"])

        for finding in findings:
            print("Finding:", finding)

# Display summary
print("\n========== SCAN SUMMARY ==========")
print("Total processes analysed:", len(processes))
print("Processes flagged:", alert_count)
print("Total findings:", sum(
    1 for process in processes
    for pattern in indicators
    if pattern in process["CommandLine"].lower()
))