import os
import io
import cv2
import base64
import requests
import secrets
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from PIL import Image
from werkzeug.utils import secure_filename
from reportlab.pdfgen import canvas
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_secret_key')


# API Keys
VIRUSTOTAL_API_KEY =  os.getenv("VIRUSTOTAL_API_KEY")

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")


UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def scan_qr_code(image_path):
    try:
        image = cv2.imread(image_path)
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(image)
        if data:
            return [data]
        return []
    except Exception as e:
        print("QR Scan Error:", e)
        return []

def check_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        params = {"url": url}
        response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)
        if response.status_code == 200:
            analysis_url = response.json()['data']['id']
            analysis_response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_url}', headers=headers)
            if analysis_response.status_code == 200:
                stats = analysis_response.json()['data']['attributes']['stats']
                return stats.get('malicious', 0), stats.get('suspicious', 0)
    except:
        pass
    return None, None

def check_google_safe_browsing(url):
    try:
        api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}'
        payload = {
            "client": {"clientId": "qr-threat-scanner", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(api_url, json=payload)
        return response.status_code == 200 and "matches" in response.json()
    except:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    if 'qr_image' not in request.files:
        flash("No file part")
        return redirect(url_for('index'))

    file = request.files['qr_image']
    if file.filename == '':
        flash("No selected file")
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    urls = scan_qr_code(filepath)
    if not urls:
        return render_template('result.html', url=None, vt_result="No QR code found", gsb_result="", risk_score="N/A")

    url = urls[0]
    vt_malicious, vt_suspicious = check_virustotal(url)
    google_safe = check_google_safe_browsing(url)

    # Risk Score
    risk_score = 0
    if vt_malicious:
        risk_score += vt_malicious * 2
    if vt_suspicious:
        risk_score += vt_suspicious
    if google_safe:
        risk_score += 5

    level = "Low Risk ✅"
    if risk_score > 7:
        level = "High Risk ⚠️"
    elif risk_score > 3:
        level = "Moderate Risk ⚠"

    session['url'] = url
    session['vt_result'] = f"Malicious: {vt_malicious}, Suspicious: {vt_suspicious}"
    session['gsb_result'] = "Unsafe" if google_safe else "Safe"
    session['risk_score'] = f"{risk_score} ({level})"

    return render_template(
        'result.html',
        url=url,
        vt_result=f"Malicious: {vt_malicious}, Suspicious: {vt_suspicious}",
        gsb_result="Unsafe ❌" if google_safe else "Safe ✔️",
        risk_score=f"{risk_score} ({level})"
    )

@app.route('/download_pdf', methods=['POST'])
def download_pdf():
    url = session.get('url', 'Unknown')
    vt_result = session.get('vt_result', 'Unknown')
    gsb_result = session.get('gsb_result', 'Unknown')
    risk_score = session.get('risk_score', 'Unknown')

    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica", 14)
    p.drawString(100, 800, "QR Scan Result Report")
    p.drawString(100, 760, f"URL: {url}")
    p.drawString(100, 740, f"VirusTotal: {vt_result}")
    p.drawString(100, 720, f"Google Safe Browsing: {gsb_result}")
    p.drawString(100, 700, f"Risk Score: {risk_score}")
    p.showPage()
    p.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name="scan_report.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

