from fpdf import FPDF
from datetime import datetime
import os

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

def generate_report(alert):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(0, 10, "NIGERIAN AIRSPACE MANAGEMENT AGENCY (NAMA)", ln=True)
    pdf.cell(0, 10, "ABUJA ATC CYBER INCIDENT REPORT", ln=True)
    pdf.ln(5)

    pdf.cell(0, 10, f"Incident Time: {alert['timestamp']}", ln=True)
    pdf.cell(0, 10, f"Airport: {alert['airport']}", ln=True)
    pdf.cell(0, 10, f"Source IP: {alert['src_ip']}", ln=True)
    pdf.cell(0, 10, f"Aircraft ICAO: {alert.get('icao','UNKNOWN')}", ln=True)
    pdf.cell(0, 10, f"Attack Type: {alert['attack']}", ln=True)
    pdf.cell(0, 10, f"Severity: {alert['severity']}", ln=True)
    pdf.cell(0, 10, f"ML Anomaly Score: {alert['score']}", ln=True)

    pdf.ln(5)
    pdf.multi_cell(0, 10,
        "Description:\n"
        "This incident indicates abnormal cyber activity affecting air traffic systems. "
        "The anomaly score exceeded acceptable thresholds, triggering automated ATC response procedures."
    )

    pdf.ln(5)
    pdf.multi_cell(0, 10,
        "Response Actions:\n"
        "- IDS detection\n"
        "- ATC alerted\n"
        "- Aircraft identity verified\n"
        "- Incident logged"
    )

    pdf.ln(5)
    pdf.multi_cell(0, 10,
        "Compliance:\n"
        "- ICAO Annex 10 (Aeronautical Telecommunications)\n"
        "- ICAO Annex 17 (Security)\n"
        "- NIST SP 800-94 (IDS)"
    )

    filename = f"{REPORT_DIR}/incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    return filename
