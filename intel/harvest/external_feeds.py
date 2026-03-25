import requests
import json
import os
import sqlite3
from datetime import datetime

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "..", "parsed_data", "parsed_intel.sqlite")
FEEDS_RESULTS = os.path.join(SCRIPT_DIR, "cache", "feeds_results.json")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_BASE = "https://api.first.org/data/v1/epss?envelope=true&pretty=true"

CACHE_DIR = os.path.join(SCRIPT_DIR, "cache")
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(FEEDS_RESULTS), exist_ok=True)

def graceful_error(module, message):
    """Handles errors gracefully without crashing the daily harvest."""
    print(f"[!] ERROR in {module}: {message}. Moving on...")

def load_cache(filename):
    """Loads a JSON file from the local cache if it exists."""
    filepath = os.path.join(CACHE_DIR, filename)
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            graceful_error("CacheLoader", f"Failed to read {filepath} - {e}")
    return None

def save_cache(filename, data):
    """Saves data to the local cache directory."""
    filepath = os.path.join(CACHE_DIR, filename)
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        graceful_error("CacheSaver", f"Failed to save {filepath} - {e}")

def fetch_cisa_kev():
    """Fetches and caches the CISA KEV catalog."""
    cache_file = "cisa_kev.json"
    cached_data = load_cache(cache_file)
    
    if cached_data:
        return cached_data

    print("[*] Fetching fresh CISA KEV catalog...")
    kev_dict = {}
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        for vuln in data.get('vulnerabilities', []):
            kev_dict[vuln['cveID']] = {
                "vulnerabilityName": vuln.get('vulnerabilityName'),
                "dateAdded": vuln.get('dateAdded'),
                "shortDescription": vuln.get('shortDescription')
            }
            
        save_cache(cache_file, kev_dict)
        return kev_dict
    except Exception as e:
        graceful_error("CISA_KEV_Fetch", str(e))
        return {}

def fetch_epss_for_cves(cve_list):
    """Fetches EPSS scores for a specific list of CVEs in batches."""
    if not cve_list:
        return {}

    unique_cves = list(set(cve_list))
    epss_dict = {}
    chunk_size = 50
    
    for i in range(0, len(unique_cves), chunk_size):
        chunk = unique_cves[i:i + chunk_size]
        cve_query = ",".join(chunk)
        url = f"{EPSS_API_BASE}&cve={cve_query}"
        
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            for item in data.get('data', []):
                epss_dict[item['cve']] = float(item.get('epss', 0.0))
                
        except Exception as e:
            graceful_error("EPSS_API_Fetch", f"Failed batch - {e}")
            
    return epss_dict

def get_breadcrumbs_from_db():
    """Retrieves all breadcrumb keywords from the SQLite database."""
    breadcrumbs = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT breadcrumb FROM breadcrumbs")
        rows = cursor.fetchall()
        # Filter for items that look like CVEs to avoid unnecessary API calls
        pattern = r"CVE-\d{4}-\d{4,7}"
        import re
        for row in rows:
            matches = re.findall(pattern, row[0].upper())
            breadcrumbs.extend(matches)
        conn.close()
    except Exception as e:
        graceful_error("DB_Breadcrumbs", str(e))
    return list(set(breadcrumbs))

def build_truth_dictionary(extracted_cves):
    """Orchestrates the fetching of KEV and EPSS data for provided CVEs."""
    print(f"[*] Building Truth Dictionary for {len(extracted_cves)} unique CVEs...")
    
    cisa_kev = fetch_cisa_kev()
    epss_scores = fetch_epss_for_cves(extracted_cves)
    
    truth_db = {}
    for cve in extracted_cves:
        truth_db[cve] = {
            "in_kev": cve in cisa_kev,
            "epss_score": epss_scores.get(cve, 0.0),
            "kev_details": cisa_kev.get(cve, None)
        }
        
    return truth_db

if __name__ == "__main__":
    print("[*] Running Threat Feeds Integrator...")
    
    # Logic: Get CVE-style breadcrumbs from the database instead of test list
    target_cves = get_breadcrumbs_from_db()
    
    if not target_cves:
        print("[!] No CVE-style breadcrumbs found in database to check.")
    else:
        truth_data = build_truth_dictionary(target_cves)
        
        # Exporting to the specified feeds_results.json location
        try:
            with open(FEEDS_RESULTS, 'w') as f:
                json.dump(truth_data, f, indent=4)
            print(f"[+] Results successfully exported to: {FEEDS_RESULTS}")
        except Exception as e:
            graceful_error("FinalExport", str(e))