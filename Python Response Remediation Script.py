import requests

# Function to enrich and respond to suspicious IP activity from a PowerShell alert
def enrich_and_notify(ip):
    vt_key = "REPLACE_VT_API"  # 🔁 Replace with your VirusTotal API key
    ab_key = "REPLACE_AB_API"  # 🔁 Replace with your AbuseIPDB API key

    # --- VirusTotal IP enrichment ---
    vt = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": vt_key}  # Use API key in header
    ).json()

    # --- AbuseIPDB IP enrichment ---
    ab = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ab_key, "Accept": "application/json"},
        params={"ipAddress": ip}  # Send IP as parameter
    ).json()

    # --- Extract scores from response ---
    vt_score = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    ab_score = ab.get("data", {}).get("abuseConfidenceScore", 0)

    print(f"[Enrichment] IP: {ip} | VT: {vt_score} | AbuseIPDB: {ab_score}")

    # --- Conditional SOAR Action ---
    if vt_score >= 10 or ab_score >= 90:
        print(f"[Action] Blocking IP {ip} via firewall or SOAR API...")  # 🔁 Replace with firewall/SOAR block logic
    else:
        print("[Action] Alert scored below threshold. Manual review recommended.")
