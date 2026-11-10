
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis_pipeline import run_analysis
from src.reporting.pdf_reporter import generate_pdf_report


def main():
    print("LOGSENTRY - PDF REPORT GENERATION")
    print("=" * 50)

    # Run the integrated analysis pipeline.
    analysis_results = run_analysis()

    # Generate the PDF report.
    report_path = generate_pdf_report(analysis_results)

    print(f"Report generated: {report_path}")
    print(f"File exists: {report_path.is_file()}")

    if report_path.is_file():
        print(f"File size: {report_path.stat().st_size} bytes")

        with report_path.open("rb") as report_file:
            pdf_header = report_file.read(5)

        print(f"PDF signature: {pdf_header!r}")
        print(f"Valid PDF signature: {pdf_header == b'%PDF-'}")

    print("\nREPORT SUMMARY")
    print("-" * 50)

    summary = analysis_results["summary"]

    for key, value in summary.items():
        print(f"{key}: {value}")

    print("\nREPORT CONTENTS")
    print("-" * 50)
    print(f"Security alerts: {len(analysis_results['alerts'])}")
    print(f"Correlated incidents: {len(analysis_results['incidents'])}")

    mappings = [
        mapping
        for alert in analysis_results["alerts"]
        if (mapping := __import__(
            "src.mitre.attack_mapper",
            fromlist=["map_alert_to_attack"],
        ).map_alert_to_attack(alert)) is not None
    ]

    print(f"MITRE ATT&CK mappings: {len(mappings)}")

    print("\nPDF REPORT GENERATION COMPLETED")


if __name__ == "__main__":
    main()
