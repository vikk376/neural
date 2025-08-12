from flask import Flask, render_template, request, send_file
import requests
import re
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO

# API KEYS
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
GEMINI_API_KEY = "AIzaSyD3NCLMy1tPVMcAY3t0NKyPZgH9GqbAtVg"
VT_API_KEY = "43e8f5352d86060ba3f59dbc8160e722776f7409119e4badaf350bb5829b5b58"

app = Flask(__name__)

# Temporary storage for last result
last_report_data = {}

def extract_iocs(text):
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    urls = re.findall(r"(https?://[^\s]+)", text)
    hashes = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
    return {"ips": list(set(ips)), "urls": list(set(urls)), "hashes": list(set(hashes))}

def virustotal_lookup(ioc, ioc_type):
    headers = {"x-apikey": VT_API_KEY}
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "url":
        url_id = requests.utils.quote(ioc, safe="")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        return None

    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        return parse_vt_data(data)
    return None

def parse_vt_data(data):
    """Extract key details from VirusTotal JSON"""
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    reputation = attributes.get("reputation", "N/A")
    #last_analysis_date = attributes.get("last_analysis_date", "N/A")

    return {
        "Malicious": stats.get("malicious", 0),
        "Suspicious": stats.get("suspicious", 0),
        "Harmless": stats.get("harmless", 0),
        "Undetected": stats.get("undetected", 0),
        "Reputation": reputation,
       # "Last Analysis Date": last_analysis_date
    }

def gemini_analysis(incident_text, vt_data):
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{
            "parts": [{
                "text": (
                    "You are a super intelligent security investigator.\n"
                    "Incident details:\n" + incident_text + "\n\n"
                    "VirusTotal findings:\n" + str(vt_data) + "\n\n"
                    "- Remove star in output\n"
                    "Please provide a detailed report including:\n"
                    "- Bold headline in output\n"
                    "- Logs to check\n"
                    "- Actions to take\n"
                    "- Remediation process\n"
                    "- Security tool improvement suggestions\n"
                    "- Give all details in short and informative and headline in bold content normal letter and remove star for bold\n"
                    "- Lessons learned\n"
                    "- Just provide KQL for Analysis using your knowledge of incident summary"
                )
            }]
        }]
    }
    response = requests.post(f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
                              headers=headers, json=payload)
    if response.status_code == 200:
        data = response.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except:
            return "Error parsing Gemini response."
    return "Gemini API request failed."

def create_pdf_report(incident_text, vt_data, ai_analysis):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 14)
    p.drawString(30, 750, "Incident Investigation Report")
    p.setFont("Helvetica", 10)

    y = 720
    p.drawString(30, y, "Incident Details:")
    y -= 15
    for line in incident_text.split("\n"):
        p.drawString(30, y, line)
        y -= 12

    y -= 20
    p.setFont("Helvetica-Bold", 12)
    p.drawString(30, y, "VirusTotal Findings:")
    p.setFont("Helvetica", 10)
    y -= 12
    for ioc, details in vt_data.items():
        p.drawString(30, y, f"{ioc}: {details}")
        y -= 12

    y -= 20
    p.setFont("Helvetica-Bold", 12)
    p.drawString(30, y, "AI Security Analysis:")
    p.setFont("Helvetica", 10)
    y -= 12
    for line in ai_analysis.split("\n"):
        if y < 50:
            p.showPage()
            y = 750
        p.drawString(30, y, line)
        y -= 12

    p.save()
    buffer.seek(0)
    return buffer

@app.route("/", methods=["GET", "POST"])
def index():
    global last_report_data
    if request.method == "POST":
        incident_text = request.form.get("incident_text")
        
        # Extract IOCs
        iocs = extract_iocs(incident_text)

        # Get VT data
        vt_results = {}
        for ip in iocs["ips"]:
            vt_results[ip] = virustotal_lookup(ip, "ip")
        for url in iocs["urls"]:
            vt_results[url] = virustotal_lookup(url, "url")
        for h in iocs["hashes"]:
            vt_results[h] = virustotal_lookup(h, "hash")

        # AI analysis
        ai_analysis = gemini_analysis(incident_text, vt_results)

        last_report_data = {
            "incident_text": incident_text,
            "vt_results": vt_results,
            "ai_analysis": ai_analysis
        }

        return render_template("result.html",
                               incident_text=incident_text,
                               vt_results=vt_results,
                               ai_analysis=ai_analysis)

    return render_template("index.html")

@app.route("/download")
def download_report():
    pdf_buffer = create_pdf_report(
        last_report_data["incident_text"],
        last_report_data["vt_results"],
        last_report_data["ai_analysis"]
    )
    return send_file(pdf_buffer, as_attachment=True,
                     download_name="incident_report.pdf",
                     mimetype="application/pdf")

if __name__ == "__main__":
    app.run(debug=True)


