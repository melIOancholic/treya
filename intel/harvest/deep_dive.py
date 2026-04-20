import os
import json
import time
import random
import trafilatura
import sys
from fake_useragent import UserAgent

# --- PATH CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CANDIDATES_FILE = os.path.normpath(os.path.join(SCRIPT_DIR, "cache", "report_candidates.json"))

def get_article_content(url):
    """
    Fetches and extracts the main text of an article using Trafilatura.
    Includes randomized delays and a fake User-Agent to be inconspicuous.
    """
    if not url or url == "No Link":
        return "No content available."

    ua = UserAgent()
    headers = {'User-Agent': ua.random}
    
    # Randomized delay between 3 and 7 seconds
    delay = random.uniform(3, 7)
    print(f"    [~] Sleeping for {delay:.2f}s before fetching: {url}")
    time.sleep(delay)

    try:
        # Download and extract
        downloaded = trafilatura.fetch_url(url)
        if downloaded:
            # We extract to markdown for better LLM structure comprehension
            result = trafilatura.extract(downloaded, include_comments=False, output_format='markdown')
            return result if result else "Extraction failed: No main content found."
        return "Extraction failed: Could not fetch URL."
    except Exception as e:
        return f"Extraction error: {str(e)}"

def main():
    # Force the stdout to use utf-8 to prevent crashes on non-standard characters
    sys.stdout.reconfigure(encoding='utf-8')

    print("[*] Starting Deep Dive Extraction Process...")
    
    if not os.path.exists(CANDIDATES_FILE):
        print(f"[!] {CANDIDATES_FILE} not found. Run topic selection first.")
        return

    with open(CANDIDATES_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for category, topics in data.items():
        print(f"\n[*] Deep Diving into Category: {category}")
        for topic in topics:
            # 1. Process Lead Article
            print(f"  [>] Lead Article: {topic.get('title')}")
            if "deep_dive_context" not in topic or not topic["deep_dive_context"]:
                topic["deep_dive_context"] = get_article_content(topic.get("link"))

            # 2. Process Supplementary Articles
            supps = topic.get("supplementary_articles", [])
            for s_idx, supp in enumerate(supps):
                print(f"  [>] Supplementary {s_idx+1}: {supp.get('title')}")
                if "deep_dive_context" not in supp or not supp["deep_dive_context"]:
                    supp["deep_dive_context"] = get_article_content(supp.get("link"))

    # Save enriched data back to candidates file
    with open(CANDIDATES_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)
    
    print(f"\n[+] Deep Dive Complete. Data enriched in: {CANDIDATES_FILE}")

if __name__ == "__main__":
    main()