import os
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER

def generate_pdf_report(scan_data: dict) -> str:
    url = scan_data.get("url", "Unknown URL")
    safe_name = url.replace("://", "_").replace("/", "_").replace("?", "_")[:50]
    output_path = f"reports/report_{safe_name}.pdf"

    os.makedirs("reports", exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'Title', parent=styles['Title'],
        fontSize=22, textColor=colors.HexColor('#1a1a2e'),
        alignment=TA_CENTER, fontName='Helvetica-Bold', spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'Subtitle', parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#4a4a8a'),
        alignment=TA_CENTER, spaceAfter=2
    )
    section_style = ParagraphStyle(
        'Section', parent=styles['Heading1'],
        fontSize=13, textColor=colors.white,
        backColor=colors.HexColor('#1a1a2e'),
        fontName='Helvetica-Bold',
        spaceBefore=12, spaceAfter=8,
        borderPadding=(6, 8, 6, 8),
    )
    heading_style = ParagraphStyle(
        'Heading', parent=styles['Heading2'],
        fontSize=11, textColor=colors.HexColor('#1a1a2e'),
        fontName='Helvetica-Bold',
        spaceBefore=8, spaceAfter=4
    )
    body_style = ParagraphStyle(
        'Body', parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#333333'),
        leading=15, spaceAfter=4
    )
    bullet_style = ParagraphStyle(
        'Bullet', parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#333333'),
        leftIndent=16, leading=14, spaceAfter=3
    )

    story = []

    # HEADER
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("URL GUARDIANS", title_style))
    story.append(Paragraph("AI-Powered Security Audit Report", subtitle_style))
    story.append(Paragraph("MCKV Institute of Engineering | BTECH/IT-1/25", subtitle_style))
    story.append(Spacer(1, 2*mm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1a1a2e')))
    story.append(Spacer(1, 4*mm))

    # SCAN INFO
    classification = scan_data.get("classification", {}).get("output", {})
    risk_level = classification.get("risk_level", "Unknown")
    risk_colors_map = {"High": "#c62828", "Medium": "#e65100", "Low": "#2e7d32"}
    risk_color = risk_colors_map.get(risk_level, "#333333")

    info_data = [
        ['Scanned URL', url],
        ['Risk Level', risk_level],
        ['Endpoint Type', classification.get("endpoint_type", "Unknown")],
        ['Tech Stack', ", ".join(classification.get("likely_tech_stack", []))],
        ['Status', scan_data.get("status", "Unknown")],
    ]
    info_table = Table(info_data, colWidths=[45*mm, 125*mm])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f0f0f8')),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (1,1), (1,1), colors.HexColor(risk_color)),
        ('FONTNAME', (1,1), (1,1), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 4*mm))

    # CLASSIFICATION
    story.append(Paragraph("Agent 1 — URL Classification", section_style))
    if classification:
        story.append(Paragraph("<b>Initial Observations:</b>", heading_style))
        story.append(Paragraph(
            classification.get("initial_observations", "No observations available."),
            body_style
        ))
        story.append(Paragraph("<b>Interesting Parameters:</b>", heading_style))
        params = classification.get("interesting_parameters", [])
        for p in params:
            story.append(Paragraph(f"• {p}", bullet_style))
        if not params:
            story.append(Paragraph("No interesting parameters found.", body_style))

        story.append(Paragraph("<b>Recommended Tests:</b>", heading_style))
        tests = classification.get("recommended_tests", [])
        for t in tests:
            story.append(Paragraph(f"• {t}", bullet_style))
        if not tests:
            story.append(Paragraph("No tests recommended.", body_style))
    else:
        story.append(Paragraph("Classification data not available.", body_style))

    # ATTACK PLAN
    story.append(Paragraph("Agent 2 — Attack Plan", section_style))
    attack_output = scan_data.get("attack_plan", {}).get("output", {})
    vulnerabilities = attack_output.get("vulnerabilities", [])

    if vulnerabilities:
        story.append(Paragraph(
            f"<b>Risk Score: {attack_output.get('estimated_risk_score', 'N/A')}/10</b>",
            heading_style
        ))
        story.append(Paragraph(attack_output.get("summary", ""), body_style))
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'Unknown')
            sev_colors_map = {"Critical": "#c62828", "High": "#e65100", "Medium": "#f57f17", "Low": "#2e7d32"}
            sev_color = sev_colors_map.get(sev, "#333333")
            vuln_style = ParagraphStyle(
                'Vuln', parent=styles['Heading2'],
                fontSize=11, textColor=colors.HexColor(sev_color),
                fontName='Helvetica-Bold', spaceBefore=8, spaceAfter=4
            )
            story.append(Paragraph(f"{vuln.get('name', '')} — {sev}", vuln_style))
            story.append(Paragraph(f"• {vuln.get('description', '')}", bullet_style))
            story.append(Paragraph(f"• Attack Vector: {vuln.get('attack_vector', '')}", bullet_style))
            story.append(Paragraph(f"• Affected Parameter: {vuln.get('affected_parameter', '')}", bullet_style))
    else:
        story.append(Paragraph("Attack plan data not available yet.", body_style))

    # PAYLOADS
    story.append(Paragraph("Agent 3 — Test Payloads", section_style))
    payload_output = scan_data.get("payloads", {}).get("output", {})
    payloads = payload_output.get("payloads", [])

    if payloads:
        for p in payloads:
            story.append(Paragraph(
                f"<b>{p.get('vulnerability', '')} — {p.get('severity', '')}</b>",
                heading_style
            ))
            for tp in p.get("test_payloads", []):
                payload_code_style = ParagraphStyle(
                    'PayloadCode', parent=styles['Normal'],
                    fontSize=9, fontName='Courier',
                    backColor=colors.HexColor('#f4f4f4'),
                    borderPadding=(4, 6, 4, 6),
                    spaceAfter=4, leading=13
                )
                story.append(Paragraph(f"Payload: {tp.get('payload', '')}", payload_code_style))
                story.append(Paragraph(f"• {tp.get('description', '')}", bullet_style))
                story.append(Paragraph(f"• Expected: {tp.get('expected_result', '')}", bullet_style))
    else:
        story.append(Paragraph("Payload data not available yet.", body_style))

    # REPORT
    story.append(Paragraph("Agent 4 — Security Report", section_style))
    report_output = scan_data.get("report", {}).get("output", {})

    if report_output.get("executive_summary"):
        story.append(Paragraph("<b>Executive Summary:</b>", heading_style))
        story.append(Paragraph(report_output.get("executive_summary", ""), body_style))
        findings = report_output.get("findings", [])
        if findings:
            story.append(Paragraph("<b>Findings:</b>", heading_style))
            for f in findings:
                story.append(Paragraph(f"• {f.get('title', '')} — {f.get('severity', '')}", bullet_style))
                story.append(Paragraph(f"  Fix: {f.get('recommendation', '')}", bullet_style))
        recommendations = report_output.get("recommendations", [])
        if recommendations:
            story.append(Paragraph("<b>Recommendations:</b>", heading_style))
            for r in recommendations:
                story.append(Paragraph(f"• {r}", bullet_style))
        story.append(Paragraph("<b>Conclusion:</b>", heading_style))
        story.append(Paragraph(report_output.get("conclusion", ""), body_style))
    else:
        story.append(Paragraph("Full report not available yet.", body_style))

    # FOOTER
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#1a1a2e')))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "URL Guardians | BTECH/IT-1/25 | MCKV Institute of Engineering, Howrah",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                       textColor=colors.HexColor('#4a4a8a'), alignment=TA_CENTER)
    ))
    story.append(Paragraph(
        "This report is for authorized security testing only.",
        ParagraphStyle('Footer2', parent=styles['Normal'], fontSize=8,
                       textColor=colors.HexColor('#888888'), alignment=TA_CENTER)
    ))

    doc.build(story)
    return output_path