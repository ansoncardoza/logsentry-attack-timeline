
import sys
import json
from pathlib import Path

# Add the project root to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis_pipeline import run_analysis
from src.reporting.json_reporter import generate_json_report


# Run the complete LogSentry analysis.
results = run_analysis()

# Generate the JSON investigation report.
report_path = generate_json_report(results)

print("\nLOGSENTRY - JSON REPORT GENERATION")
print("=" * 50)

print(f"Report generated: {report_path}")
print(f"File exists: {report_path.is_file()}")
print(f"File size: {report_path.stat().st_size} bytes")

# Read the generated JSON report.
with report_path.open("r", encoding="utf-8") as report_file:
    report = json.load(report_file)

print("\nREPORT SUMMARY")
print("-" * 50)

for key, value in report["summary"].items():
    print(f"{key.replace('_', ' ').title()}: {value}")

print("\nREPORT CONTENTS")
print("-" * 50)

print(f"Security alerts: {len(report['alerts'])}")
print(f"Correlated incidents: {len(report['incidents'])}")
print(f"Incident results: {len(report['incident_results'])}")

print("\nJSON REPORT VALIDATION")
print("-" * 50)

print("Valid JSON: Yes")
print("Required sections: Present")
print("REPORT GENERATION COMPLETED")
