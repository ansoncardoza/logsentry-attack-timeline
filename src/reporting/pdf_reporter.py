
import html
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)

from src.mitre.attack_mapper import map_alert_to_attack


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _safe_text(value):
    """Convert a value into text that is safe for ReportLab Paragraphs."""

    if value is None:
        return "Not available"

    if isinstance(value, (list, tuple, set)):
        value = ", ".join(str(item) for item in value)

    return html.escape(str(value))


def _make_table(data, widths=None):
    """Create a consistently styled PDF table."""

    table = Table(
        data,
        colWidths=widths,
        repeatRows=1,
        hAlign="LEFT",
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243447")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEADING", (0, 0), (-1, -1), 11),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white,
            colors.HexColor("#F1F5F9"),
        ]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    return table


def _add_page_number(canvas, document):
    """Add page numbers to the bottom of each PDF page."""

    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))

    canvas.drawString(
        20 * mm,
        12 * mm,
        "LogSentry - Security Investigation Report",
    )

    canvas.drawRightString(
        190 * mm,
        12 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


def generate_pdf_report(analysis_results, output_path=None):
    """
    Generate a PDF investigation report from run_analysis() results.

    Returns:
        Path to the generated PDF report.
    """

    if not isinstance(analysis_results, dict):
        raise TypeError("Analysis results must be a dictionary.")

    required_sections = [
        "summary",
        "parsed_events",
        "alerts",
        "incidents",
        "incident_results",
    ]

    for section in required_sections:
        if section not in analysis_results:
            raise ValueError(
                f"Analysis results are missing the '{section}' section."
            )

    if output_path is None:
        output_path = (
            PROJECT_ROOT
            / "reports"
            / "logsentry_report.pdf"
        )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "LogSentryTitle",
        parent=styles["Title"],
        fontSize=21,
        leading=26,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#243447"),
        spaceAfter=8,
    )

    heading_style = ParagraphStyle(
        "LogSentryHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#243447"),
        spaceBefore=14,
        spaceAfter=7,
    )

    subheading_style = ParagraphStyle(
        "LogSentrySubheading",
        parent=styles["Heading3"],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#334155"),
        spaceBefore=8,
        spaceAfter=4,
    )

    body_style = ParagraphStyle(
        "LogSentryBody",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=12,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "LogSentrySmall",
        parent=body_style,
        fontSize=7.5,
        leading=10,
    )

    story = []

    summary = analysis_results["summary"]
    alerts = analysis_results["alerts"]
    incidents = analysis_results["incidents"]
    incident_results = analysis_results["incident_results"]

    generated_at = datetime.now(timezone.utc).isoformat()

    # --------------------------------------------------
    # Report title and metadata
    # --------------------------------------------------

    story.append(Paragraph("LOGSENTRY", title_style))

    story.append(Paragraph(
        "Security Investigation Report",
        ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            alignment=TA_CENTER,
            fontSize=11,
            textColor=colors.HexColor("#475569"),
        ),
    ))

    story.append(Spacer(1, 8))

    story.append(Paragraph(
        f"<b>Generated:</b> {_safe_text(generated_at)}",
        body_style,
    ))

    story.append(Paragraph(
        "<b>Report version:</b> 1.0",
        body_style,
    ))

    story.append(Spacer(1, 8))

    # --------------------------------------------------
    # Executive summary
    # --------------------------------------------------

    story.append(Paragraph("1. Executive Summary", heading_style))

    story.append(Paragraph(
        "This report summarizes the results of LogSentry log analysis. "
        "It includes parsed events, security detections, MITRE ATT&amp;CK "
        "mappings, and correlated incident information.",
        body_style,
    ))

    summary_rows = [
        ["Metric", "Result"],
        ["Authentication Events", str(summary.get("authentication_events", 0))],
        ["Apache Events", str(summary.get("apache_events", 0))],
        ["Firewall Events", str(summary.get("firewall_events", 0))],
        ["Total Events", str(summary.get("total_events", 0))],
        ["Brute Force Alerts", str(summary.get("brute_force_alerts", 0))],
        ["Port Scan Alerts", str(summary.get("port_scan_alerts", 0))],
        ["Web Path Alerts", str(summary.get("web_path_alerts", 0))],
        ["Total Security Alerts", str(summary.get("total_alerts", 0))],
        ["Correlated Incidents", str(summary.get("total_incidents", 0))],
    ]

    story.append(_make_table(
        summary_rows,
        widths=[85 * mm, 85 * mm],
    ))

    # --------------------------------------------------
    # Security alerts
    # --------------------------------------------------

    story.append(Paragraph("2. Security Alert Details", heading_style))

    if not alerts:
        story.append(Paragraph(
            "No security alerts were generated.",
            body_style,
        ))

    for index, alert in enumerate(alerts, start=1):
        alert_type = _safe_text(alert.get("alert_type"))
        source_ip = _safe_text(alert.get("source_ip"))
        severity = _safe_text(alert.get("severity"))

        story.append(Paragraph(
            f"Alert {index}: {alert_type}",
            subheading_style,
        ))

        alert_rows = [
            ["Field", "Value"],
            ["Severity", severity],
            ["Source IP", source_ip],
        ]

        for field in (
            "destination_ip",
            "failed_attempts",
            "distinct_ports",
            "destination_ports",
            "distinct_paths",
            "suspicious_paths",
            "request_count",
            "first_seen",
            "last_seen",
            "actions",
            "description",
        ):
            if field in alert:
                alert_rows.append([
                    _safe_text(field.replace("_", " ").title()),
                    Paragraph(_safe_text(alert[field]), small_style),
                ])

        story.append(_make_table(
            alert_rows,
            widths=[45 * mm, 125 * mm],
        ))

        story.append(Spacer(1, 7))

    # --------------------------------------------------
    # MITRE ATT&CK mappings
    # --------------------------------------------------

    story.append(Paragraph(
        "3. MITRE ATT&amp;CK Technique Mapping",
        heading_style,
    ))

    mappings = [
        mapping
        for alert in alerts
        if (mapping := map_alert_to_attack(alert)) is not None
    ]

    if mappings:
        mapping_rows = [[
            "Detection",
            "Technique",
            "Technique ID",
            "Tactic",
        ]]

        for alert, mapping in zip(
            [
                alert for alert in alerts
                if map_alert_to_attack(alert) is not None
            ],
            mappings,
        ):
            mapping_rows.append([
                Paragraph(_safe_text(alert.get("alert_type")), small_style),
                Paragraph(_safe_text(mapping.get("technique")), small_style),
                _safe_text(mapping.get("technique_id")),
                Paragraph(_safe_text(mapping.get("tactic")), small_style),
            ])

        story.append(_make_table(
            mapping_rows,
            widths=[43 * mm, 57 * mm, 30 * mm, 40 * mm],
        ))

        for mapping in mappings:
            rationale = mapping.get("rationale")

            if rationale:
                story.append(Paragraph(
                    f"<b>{_safe_text(mapping.get('technique_id'))}:</b> "
                    f"{_safe_text(rationale)}",
                    small_style,
                ))

    else:
        story.append(Paragraph(
            "No MITRE ATT&amp;CK mappings were generated.",
            body_style,
        ))

    # --------------------------------------------------
    # Correlated incidents and timelines
    # --------------------------------------------------

    story.append(Paragraph(
        "4. Correlated Incident Investigation",
        heading_style,
    ))

    if not incident_results:
        story.append(Paragraph(
            "No correlated incidents were identified in this analysis. "
            "The alerts remain separate because the current sample logs "
            "contain different source IP addresses.",
            body_style,
        ))

    for result in incident_results:
        incident = result.get("incident", {})
        timeline = result.get("timeline", [])

        story.append(Paragraph(
            f"Incident: {_safe_text(incident.get('incident_id'))}",
            subheading_style,
        ))

        story.append(Paragraph(
            f"<b>Source IP:</b> {_safe_text(incident.get('source_ip'))}<br/>"
            f"<b>Alert count:</b> {_safe_text(incident.get('alert_count'))}<br/>"
            f"<b>First seen:</b> {_safe_text(incident.get('first_seen'))}<br/>"
            f"<b>Last seen:</b> {_safe_text(incident.get('last_seen'))}<br/>"
            f"<b>Description:</b> {_safe_text(incident.get('description'))}",
            body_style,
        ))

        if timeline:
            story.append(Paragraph(
                "Chronological Attack Timeline",
                subheading_style,
            ))

            timeline_rows = [[
                "Timestamp (UTC)",
                "Event",
                "Severity",
                "Description",
            ]]

            for event in timeline:
                timeline_rows.append([
                    Paragraph(_safe_text(event.get("timestamp")), small_style),
                    Paragraph(_safe_text(event.get("event_type")), small_style),
                    _safe_text(event.get("severity")),
                    Paragraph(_safe_text(event.get("description")), small_style),
                ])

            story.append(_make_table(
                timeline_rows,
                widths=[40 * mm, 43 * mm, 22 * mm, 65 * mm],
            ))

    # --------------------------------------------------
    # Investigation limitations
    # --------------------------------------------------

    story.append(Paragraph(
        "5. Investigation Limitations and Disclaimer",
        heading_style,
    ))

    limitations = [
        "Security alerts indicate potentially suspicious activity; "
        "they do not prove that a system was compromised.",
        "A shared source IP, NAT gateway, or proxy can represent multiple "
        "different users or devices.",
        "Missing, incomplete, or incorrectly timestamped logs can affect "
        "detection and event correlation.",
        "MITRE ATT&amp;CK mappings provide behavioral context and do not "
        "confirm attacker identity or intent.",
        "This report is based only on the log records supplied to LogSentry.",
    ]

    for limitation in limitations:
        story.append(Paragraph(
            f"&bull; {_safe_text(limitation)}",
            body_style,
        ))

    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "LogSentry is a log analysis and investigation support tool. "
        "Findings should be validated against additional authorized "
        "evidence before drawing conclusions.",
        body_style,
    ))

    # --------------------------------------------------
    # Generate the PDF
    # --------------------------------------------------

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title="LogSentry Security Investigation Report",
        author="LogSentry",
    )

    document.build(
        story,
        onFirstPage=_add_page_number,
        onLaterPages=_add_page_number,
    )

    return output_path
