from fpdf import FPDF

def generate_report(alert=None):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Abuja ATC IDS Incident Report", ln=True, align="C")

    if alert:
        pdf.set_font("Arial", "", 12)
        for k,v in alert.items():
            pdf.cell(0, 8, f"{k}: {v}", ln=True)

    pdf.output("latest_incident.pdf")
