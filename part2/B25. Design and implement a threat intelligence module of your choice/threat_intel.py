"""
B25: Threat Intelligence Module — IP Reputation Checker
========================================================
Queries the AbuseIPDB API to assess the reputation of IP addresses.
Classifies each IP as Clean, Suspicious, or Malicious based on its
abuse confidence score, and produces a structured threat report.

Usage:
    python3 threat_intel.py

Requirements:
    pip install requests python-dotenv

Configuration:
    Set ABUSEIPDB_API_KEY in a .env file or as an environment variable.
    Example .env:
        ABUSEIPDB_API_KEY=your_key_here
"""

import json
import os
import time
from datetime import datetime
from typing import Optional

import requests

# ── Configuration ─────────────────────────────────────────────────────────────

# Load API key from environment or .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
API_URL = "https://api.abuseipdb.com/api/v2/check"

# Classification thresholds (abuse confidence score 0-100)
THRESHOLDS = {
    "malicious":   75,   # score >= 75 → Malicious
    "suspicious":  25,   # score >= 25 → Suspicious
    # score <  25 → Clean
}

# ── Test IP list ───────────────────────────────────────────────────────────────
# A mix of known malicious IPs (from public threat intel reports),
# legitimate services, and neutral addresses for comparison.

TEST_IPS = [
    # Known malicious / frequently reported
    ("185.220.101.45",  "Tor exit node — frequently reported"),
    ("89.248.165.101",  "Known scanner — Shodan/mass scanning"),
    ("193.32.162.157",  "Reported C2 / botnet infrastructure"),
    ("45.33.32.156",    "Scanme.nmap.org — intentional scan target"),

    # Legitimate services
    ("8.8.8.8",         "Google Public DNS"),
    ("1.1.1.1",         "Cloudflare DNS"),
    ("208.67.222.222",  "OpenDNS"),

    # Neutral / unknown
    ("192.168.1.1",     "Private network gateway — RFC 1918"),
]

# ── Core module ───────────────────────────────────────────────────────────────

class ThreatIntelModule:
    """
    IP Reputation Checker using AbuseIPDB.

    Queries each IP against the AbuseIPDB threat intelligence database,
    classifies the result, and produces a structured threat report.
    """

    def __init__(self, api_key: str):
        if not api_key:
            raise ValueError(
                "API key is required. Set ABUSEIPDB_API_KEY in your environment "
                "or .env file."
            )
        self.api_key = api_key
        self.results: list[dict] = []
        self.errors: list[str] = []

    def check_ip(self, ip: str, description: str = "") -> Optional[dict]:
        """
        Query AbuseIPDB for a single IP address.
        Returns a structured result dict, or None on error.
        """
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True,
        }

        try:
            response = requests.get(
                API_URL, headers=headers, params=params, timeout=10
            )
            response.raise_for_status()
            data = response.json().get("data", {})

            score = data.get("abuseConfidenceScore", 0)
            classification = self._classify(score)

            result = {
                "ip":                  ip,
                "description":         description,
                "classification":      classification,
                "abuse_score":         score,
                "country":             data.get("countryCode", "N/A"),
                "isp":                 data.get("isp", "N/A"),
                "domain":              data.get("domain", "N/A"),
                "total_reports":       data.get("totalReports", 0),
                "distinct_users":      data.get("numDistinctUsers", 0),
                "last_reported":       data.get("lastReportedAt", "Never"),
                "is_tor":              data.get("isTor", False),
                "usage_type":          data.get("usageType", "N/A"),
                "queried_at":          datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            return result

        except requests.exceptions.HTTPError as e:
            msg = f"HTTP error for {ip}: {e}"
            self.errors.append(msg)
            print(f"  [!] {msg}")
            return None
        except requests.exceptions.RequestException as e:
            msg = f"Request failed for {ip}: {e}"
            self.errors.append(msg)
            print(f"  [!] {msg}")
            return None

    def scan(self, ip_list: list[tuple[str, str]], delay: float = 1.0):
        """
        Scan a list of (ip, description) tuples.
        Adds a delay between requests to respect API rate limits.
        """
        print(f"\n  Scanning {len(ip_list)} IP addresses...\n")
        for i, (ip, description) in enumerate(ip_list):
            print(f"  [{i+1}/{len(ip_list)}] Checking {ip:<20} ({description})")
            result = self.check_ip(ip, description)
            if result:
                self.results.append(result)
                marker = self._marker(result["classification"])
                print(f"         {marker} Score: {result['abuse_score']:>3}/100  "
                      f"│ {result['classification']:<12} "
                      f"│ Reports: {result['total_reports']:<5} "
                      f"│ Country: {result['country']}")
            if i < len(ip_list) - 1:
                time.sleep(delay)

    def print_report(self):
        """Print a formatted threat intelligence report to the terminal."""
        print("\n" + "=" * 72)
        print("THREAT INTELLIGENCE REPORT — IP Reputation Check")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source:    AbuseIPDB (https://www.abuseipdb.com)")
        print(f"IPs scanned: {len(self.results)}")
        print("=" * 72)

        # Group by classification
        for classification in ["Malicious", "Suspicious", "Clean"]:
            group = [r for r in self.results if r["classification"] == classification]
            if not group:
                continue
            marker = self._marker(classification)
            print(f"\n{marker} {classification.upper()} ({len(group)} IPs)")
            print("-" * 72)
            for r in group:
                print(f"  IP:            {r['ip']}")
                print(f"  Description:   {r['description']}")
                print(f"  Abuse Score:   {r['abuse_score']}/100")
                print(f"  Country:       {r['country']}")
                print(f"  ISP:           {r['isp']}")
                print(f"  Domain:        {r['domain']}")
                print(f"  Usage Type:    {r['usage_type']}")
                print(f"  Total Reports: {r['total_reports']} "
                      f"(by {r['distinct_users']} distinct users)")
                print(f"  Last Reported: {r['last_reported']}")
                print(f"  Tor Exit Node: {'Yes' if r['is_tor'] else 'No'}")
                print()

        # Summary statistics
        scores = [r["abuse_score"] for r in self.results]
        malicious  = sum(1 for r in self.results if r["classification"] == "Malicious")
        suspicious = sum(1 for r in self.results if r["classification"] == "Suspicious")
        clean      = sum(1 for r in self.results if r["classification"] == "Clean")

        print("=" * 72)
        print("SUMMARY")
        print("-" * 72)
        print(f"  Total IPs scanned:  {len(self.results)}")
        print(f"  ✗ Malicious:        {malicious}")
        print(f"  ⚠ Suspicious:       {suspicious}")
        print(f"  ✓ Clean:            {clean}")
        if scores:
            print(f"  Avg abuse score:    {sum(scores)/len(scores):.1f}/100")
            print(f"  Max abuse score:    {max(scores)}/100")
        if self.errors:
            print(f"  Errors:             {len(self.errors)}")
        print("=" * 72)

    def save_report(self, filename: str = "threat_report.json"):
        """Save the full results to a JSON file for evidence."""
        report = {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "AbuseIPDB",
            "total_scanned": len(self.results),
            "results": self.results,
            "errors": self.errors,
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  [+] Report saved to {filename}")

    def _classify(self, score: int) -> str:
        if score >= THRESHOLDS["malicious"]:
            return "Malicious"
        elif score >= THRESHOLDS["suspicious"]:
            return "Suspicious"
        return "Clean"

    def _marker(self, classification: str) -> str:
        return {"Malicious": "✗", "Suspicious": "⚠", "Clean": "✓"}.get(
            classification, "?"
        )


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 72)
    print("B25: Threat Intelligence Module — IP Reputation Checker")
    print("=" * 72)

    api_key = API_KEY
    if not api_key:
        print("\n[!] No API key found.")
        print("    Set ABUSEIPDB_API_KEY as an environment variable, or")
        print("    create a .env file with: ABUSEIPDB_API_KEY=your_key_here")
        return

    module = ThreatIntelModule(api_key)
    module.scan(TEST_IPS, delay=1.0)
    module.print_report()
    module.save_report("threat_report.json")
    print()


if __name__ == "__main__":
    main()
