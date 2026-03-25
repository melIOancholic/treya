import os
import json
import sqlite3
import re
import yaml
from datetime import datetime
import pandas as pd
from jinja2 import Template
import nvdlib
import ollama
import asyncio
import random
import time
import requests
from crawl4ai import AsyncWebCrawler

# Optional enrichment library
try:
    from pyattck import Attck
    attck = Attck()
except ImportError:
    attck = None

# ==============================================================================
# CONFIGURATION & PATHS
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 
SQLITE_DB_PATH = os.path.join(BASE_DIR, "parsed_data", "parsed_intel.sqlite")
WATCHLIST_PATH = os.path.join(BASE_DIR, "memory", "watchlist.json")
REPORT_OUT_PATH = os.path.join(BASE_DIR, "memory", "last_report.json")
PROJECT_ROOT = os.path.dirname(BASE_DIR) 
YAML_PATH = os.path.join(PROJECT_ROOT, "prompts", "report", "report_module.yaml")
J2_PATH = os.path.join(PROJECT_ROOT, "prompts", "report", "report_prompt.j2")

CATEGORIES = ["threat_intelligence", "general_news", "academic_research", "community_pulse"]
CUSTOM_TOPICS = ["mergers_acquisitions", "quantum_technology", "identity_and_access_management", "supply_chain_risks"]
MAX_SECTIONS_PER_CATEGORY = 3

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def load_watchlist():
    """Loads the watchlist keywords to prioritize selection."""
    print("[*] Loading watchlist...")
    if not os.path.exists(WATCHLIST_PATH):
        print("[!] Watchlist not found. Proceeding without priority keywords.")
        return []
    try:
        with open(WATCHLIST_PATH, 'r') as f:
            data = json.load(f)
            return [item.get("name", "").lower() for item in data.get("watchlist", [])]
    except Exception as e:
        print(f"[!] Error loading watchlist: {e}")
        return []

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    if not os.path.exists(SQLITE_DB_PATH):
        raise FileNotFoundError(f"Database not found at {SQLITE_DB_PATH}")
    return sqlite3.connect(SQLITE_DB_PATH)

async def fetch_full_text(url):
    """
    Waterfall Extraction Method:
    1. Try Jina AI (Fast, No Headless Browser)
    2. Fallback to Crawl4AI (Local Headless Browser for JS-heavy sites)
    """
    sleep_time = random.uniform(3.0, 7.0)
    print(f"      [-] Pausing for {sleep_time:.2f} seconds to prevent rate-limiting...")
    await asyncio.sleep(sleep_time)

    print(f"      [-] Fetching via Jina AI: {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(f"https://r.jina.ai/{url}", headers=headers, timeout=15)
        if response.status_code == 200 and len(response.text) > 200:
            print("      [+] Jina AI success.")
            return response.text
    except Exception as e:
        print(f"      [!] Jina AI failed: {e}")

    print("      [-] Falling back to local Crawl4AI...")
    try:
        async with AsyncWebCrawler() as crawler:
            result = await crawler.arun(url=url)
            if result.success:
                print("      [+] Crawl4AI success.")
                return result.markdown
            else:
                print("      [!] Crawl4AI returned unsuccessful status.")
    except Exception as e:
        print(f"      [!] Crawl4AI failed: {e}")

    return "Content extraction failed or returned empty."

def select_articles_for_group(df, group_name, is_custom_topic=False, watchlist=[]):
    """
    Programmatically groups articles into 3 topics per category.
    Ensures 1 master and 2 supplementary articles from distinct sources.
    """
    # Filter by category or search tags for custom topics
    if is_custom_topic:
        # Search for custom topic keywords in tags or description
        search_term = group_name.replace("_", " ")
        mask = df['tags'].str.contains(search_term, case=False, na=False) | \
               df['description'].str.contains(search_term, case=False, na=False)
        subset = df[mask].copy()
    else:
        subset = df[df['category'] == group_name].copy()

    if subset.empty:
        return []

    # Score articles based on watchlist
    def score_row(row):
        text = str(row['title']).lower() + " " + str(row['tags']).lower()
        return sum(1 for w in watchlist if w in text)
    
    subset['score'] = subset.apply(score_row, axis=1)
    subset = subset.sort_values(by=['score', 'published'], ascending=[False, False])

    # Grouping logic: Pick top 3 "tags" as topics, then get 3 distinct sources per tag
    topics_selected = []
    used_sources = set()

    for _, row in subset.iterrows():
        if len(topics_selected) >= MAX_SECTIONS_PER_CATEGORY:
            break
            
        # Use primary tag as a makeshift topic cluster
        primary_tag = str(row['tags']).split(',')[0] if pd.notna(row['tags']) else "general_update"
        
        # Find 3 distinct sources sharing this tag (or fallback to just latest)
        cluster = subset[subset['tags'].str.contains(primary_tag, case=False, na=False, regex=False)]
        
        # Deduplicate by source
        unique_cluster = cluster.drop_duplicates(subset=['source_name']).head(3)
        
        if len(unique_cluster) == 3:
            # We found a valid cluster of 3 distinct sources
            topics_selected.append({
                "temp_topic_cluster": primary_tag,
                "articles": unique_cluster.to_dict('records')
            })
            # Remove these from subset to avoid reuse
            subset = subset[~subset['link'].isin(unique_cluster['link'])]

    return topics_selected

def load_templates():
    """Loads the Jinja2 template and YAML config for Ollama."""
    print("[*] Loading AI prompt templates...")
    try:
        with open(YAML_PATH, 'r') as f:
            config = yaml.safe_load(f)
        with open(J2_PATH, 'r') as f:
            template = Template(f.read())
        return template, config
    except Exception as e:
        print(f"[!] Warning: Could not load templates ({e}). Will use fallback prompt.")
        return None, None

def generate_ai_report(raw_intel_text, template, config):
    """Uses Ollama Llama 3.2 to read the raw intel and generate the report."""
    print("      [-] Asking Llama 3.2 to write report...")
    
    if template and config:
        prompt = template.render(intel=raw_intel_text, config=config)
    else:
        prompt = f"Analyze the following cybersecurity news and write a comprehensive report section outlining the main topic, key insights, and actionable advice.\n\nRAW INTEL:\n{raw_intel_text}"
    
    try:
        response = ollama.chat(model='llama3.2', messages=[
            {'role': 'system', 'content': 'You are a senior cybersecurity intelligence analyst.'},
            {'role': 'user', 'content': prompt}
        ])
        return response['message']['content']
    except Exception as e:
        print(f"      [!] Ollama generation failed: {e}")
        return "Report generation failed. Please check Ollama status."

def identify_topic_name(raw_intel_text):
    """Uses Ollama to generate a concise 3-5 word topic name based on the intel."""
    prompt = f"Based on the following news, provide a concise 3 to 6 word title/topic that groups them together. Only output the title, no other text.\n\n{raw_intel_text[:2000]}"
    try:
        response = ollama.chat(model='llama3.2', messages=[{'role': 'user', 'content': prompt}])
        return response['message']['content'].strip(' "\'')
    except:
        return "Intelligence Update"

# ==============================================================================
# MAIN ASYNC WORKFLOW
# ==============================================================================

async def main():
    print("="*60)
    print("  CYBERSECURITY INTELLIGENCE HARVESTER (2026 Edition)")
    print("="*60)

    # 1. Setup
    watchlist = load_watchlist()
    template, config = load_templates()
    
    print("[*] Connecting to database...")
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM raw_news ORDER BY published DESC LIMIT 500", conn)
    conn.close()

    final_report_data = {
        "last_harvest_date": datetime.now().strftime("%Y-%m-%d"),
        "last_harvest": []
    }

    groups_to_process = [(cat, False) for cat in CATEGORIES] + [(top, True) for top in CUSTOM_TOPICS]

    # 2. Process Categories and Topics
    entry_counter = 1
    
    for group_name, is_custom in groups_to_process:
        print(f"\n[*] Scanning for group: {group_name.upper()}")
        
        topic_clusters = select_articles_for_group(df, group_name, is_custom, watchlist)
        
        if not topic_clusters:
            print(f"    [-] Not enough distinct data to form 3 topics for {group_name}.")
            continue

        for i, cluster in enumerate(topic_clusters):
            print(f"\n  [>] Preparing Topic {i+1} for {group_name}")
            raw_intel_combined = ""
            links_metadata = []

            # 3. Waterfall Extraction
            for idx, article in enumerate(cluster['articles']):
                role = "MASTER" if idx == 0 else "SUPPLEMENTAL"
                url = article['link']
                source = article['source_name']
                
                print(f"    -> [{role}] ({source}): {article['title'][:50]}...")
                
                # Fetch text via Jina/Crawl4AI
                full_text = await fetch_full_text(url)
                
                # Deduplication Strategy: Clear source headers to help Llama synthesize
                raw_intel_combined += f"\n\n{'='*40}\nSOURCE: {source}\nURL: {url}\n{'='*40}\n"
                raw_intel_combined += full_text[:5000] # Cap at 5000 chars per article to save context window
                
                links_metadata.append({
                    "source": source,
                    "url": url
                })

            # 4. AI Processing (Topic Naming & Report Gen)
            ai_topic_name = identify_topic_name(raw_intel_combined)
            print(f"    [+] AI Identified Topic: {ai_topic_name}")
            
            final_report_text = generate_ai_report(raw_intel_combined, template, config)
            print("    [+] Report segment generated successfully.")

            # 5. Append to JSON structure
            final_report_data["last_harvest"].append({
                "category": group_name,
                "entry": entry_counter,
                "topic": ai_topic_name,
                "raw_intel": raw_intel_combined,
                "report": final_report_text,
                "links": links_metadata
            })
            entry_counter += 1

    # 6. Save Final Output
    print("\n" + "="*60)
    print("[*] Harvesting complete. Saving to memory...")
    
    os.makedirs(os.path.dirname(REPORT_OUT_PATH), exist_ok=True)
    with open(REPORT_OUT_PATH, 'w') as f:
        json.dump(final_report_data, f, indent=4)
        
    print(f"[+] Successfully wrote intelligence report to: {REPORT_OUT_PATH}")
    print("="*60)

if __name__ == "__main__":
    # Ensure asyncio event loop runs properly on Windows
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())