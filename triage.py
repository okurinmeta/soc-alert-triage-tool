import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    data = response.json()["data"]
    return {
        "ip": ip,
        "abuse_score": data["abuseConfidenceScore"],
        "total_reports": data["totalReports"],
        "country": data.get("countryCode", "Unknown"),
        "isp": data.get("isp", "Unknown"),
    }


def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    response = requests.get(url, headers=headers)
    data = response.json()["data"]["attributes"]
    stats = data["last_analysis_stats"]
    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "undetected": stats["undetected"],
    }


def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    requests.post(url, data=payload)


def triage_ip(ip):
    print(f"\nChecking IP: {ip}")
    abuse_result = check_abuseipdb(ip)
    vt_result = check_virustotal(ip)
    print(f"AbuseIPDB Score: {abuse_result['abuse_score']}% | Reports: {abuse_result['total_reports']}")
    print(f"VirusTotal: {vt_result['malicious']} malicious / {vt_result['suspicious']} suspicious flags")

    is_malicious = abuse_result["abuse_score"] >= 50 or vt_result["malicious"] >= 3

    if is_malicious:
        alert_msg = (
            f"THREAT DETECTED\n"
            f"IP: {ip}\n"
            f"AbuseIPDB Score: {abuse_result['abuse_score']}%\n"
            f"Reports: {abuse_result['total_reports']}\n"
            f"VirusTotal Malicious: {vt_result['malicious']}\n"
            f"Country: {abuse_result['country']}\n"
            f"ISP: {abuse_result['isp']}"
        )
        send_telegram_alert(alert_msg)
        print("ALERT SENT to Telegram!")
    else:
        print("IP looks clean.")


if __name__ == "__main__":
    test_ip = input("Enter an IP address to check: ")
    triage_ip(test_ip)

             





