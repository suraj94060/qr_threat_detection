import os
import base64
import requests
from flask import Flask, request, render_template, redirect
from PIL import Image
import cv2

app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
def calculate_risk_score(vt_result: str, gsb_result: str) -> int:
    score = 0
    
    # Check if VirusTotal result mentions malicious URLs
    if "Malicious:" in vt_result:
        malicious = int(vt_result.split("Malicious:")[1].split(",")[0].strip())
        if malicious > 0:
            score += 70

    # Check if result mentions suspicious
    if "Suspicious:" in vt_result:
        suspicious = int(vt_result.split("Suspicious:")[1].split(",")[0].strip())
        if suspicious > 0:
            score += 40

    # Add score if Google Safe Browsing says the site is unsafe
    if "❌" in gsb_result or "Unsafe" in gsb_result:
        score += 80

    # Cap score at 100
    return min(score, 100)

def scan_qr_code(image_path):
    try:
        image = cv2.imread(image_path)
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(image)
        return data if data else None
    except Exception as e:
        print("QR Scan Error:", e)
        return None
def check_url_with_virustotal(url):
    try:
        # Submit URL for scanning
        vt_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        data = {"url": url}

        response = requests.post(vt_url, headers=headers, data=data)
        if response.status_code != 200:
            print("VirusTotal submission failed:", response.text)
            return "❌ Failed to submit to VirusTotal."

        # Proper base64-encoded scan ID
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        result_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        result_response = requests.get(result_url, headers=headers)

        if result_response.status_code != 200:
            print("VirusTotal result error:", result_response.text)
            return "❌ Failed to get VirusTotal scan result."

        result_data = result_response.json()
        stats = result_data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0 or suspicious > 0:
            return f"⚠️ Malicious/Suspicious URL detected! (Malicious: {malicious}, Suspicious: {suspicious})"
        else:
            return "✅ Safe link (VirusTotal: No threats found)"
    except Exception as e:
        print("VirusTotal Exception:", str(e))
        return "❌ VirusTotal scan failed."
def check_url_with_google_safe_browsing(url):
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {
                "clientId": "qr-threat-checker",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = requests.post(api_url, json=payload)
        print("GSB Response:", response.status_code, response.text)
        
        if response.status_code != 200:
            return "❌ Google Safe Browsing check failed"

        if "matches" in response.json():
            return "❌ ⚠️ Unsafe URL detected by Google Safe Browsing!"
        else:
            return "✔️ Safe according to Google Safe Browsing"
    except Exception as e:
        print("Google Safe Browsing Error:", e)
        return "❌ GSB check failed"

@app.route("/", methods=["GET", "POST"])
def upload_qr():
    result = ""
    vt_result = ""
    gsb_result = ""
    risk_score = ""

    if request.method == "POST":
        file = request.files.get("qr_image")
        if not file:
            result = "❌ No file uploaded"
            return render_template("index.html", result=result)

        filepath = os.path.join("uploads", file.filename)
        os.makedirs("uploads", exist_ok=True)
        file.save(filepath)

        url = scan_qr_code(filepath)
        print("Scanned URL:", url)
        if url:
            result = f"🔍 Scanned URL: {url}"
            vt_result = check_url_with_virustotal(url)
            gsb_result = check_url_with_google_safe_browsing(url)
            risk_score = calculate_risk_score(vt_result, gsb_result)

        else:
            result = "❌ QR code does not contain a valid URL."

        os.remove(filepath)
   

    return render_template("index.html", result=result, vt_result=vt_result, gsb_result=gsb_result,risk_score=risk_score)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


