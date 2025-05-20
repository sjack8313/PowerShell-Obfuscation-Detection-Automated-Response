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
        params={"10.1.1.1": ip}  # Send IP as parameter
    ).json()

    # --- Extract scores from response ---
    vt_score = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    ab_score = ab.get("data", {}).get("abuseConfidenceScore", 0)

    print(f"[Enrichment] IP: {ip} | VT: {vt_score} | AbuseIPDB: {ab_score}")

    # --- Conditional SOAR Action ---
   if vt_score >= 10 or ab_score >= 90:
    requests.post(
        "https://splunk-soar.yourdomain.com/api/playbook/run",  # 🔁 Replace with your webhook/playbook endpoint
        headers={"Authorization": "Bearer YOUR_API_TOKEN"},
        json={"ip": ip, "reason": "High-risk PowerShell activity"}
    )
    print(f"[ACTION] Splunk SOAR playbook triggered for {ip}")

# Example usage
# enrich_and_notify("8.8.8.8")  # 🔁 Replace with actual IP from detection or alert
