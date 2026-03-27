import os
import json
import yaml
import requests
from datetime import datetime, timedelta
from jinja2 import Environment, FileSystemLoader

# --- PATH CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Input paths
CANDIDATES_FILE = os.path.normpath(os.path.join(SCRIPT_DIR, "cache", "report_candidates.json"))
COVERED_CACHE_FILE = os.path.normpath(os.path.join(SCRIPT_DIR, "cache", "already_covered.json"))
YAML_FILE = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "..", "prompts", "report", "report_module.yaml"))

# Output paths
OUTPUT_FILE = os.path.normpath(os.path.join(SCRIPT_DIR, "cache", "last_report.json"))
J2_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "..", "prompts", "report"))
J2_TEMPLATE_NAME = "report_prompt.j2"

# Ollama Configuration
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2"

def load_json(filepath):
    """Safely load a JSON file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"[!] Cannot find JSON file at: {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_yaml(filepath):
    """Safely load a YAML file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"[!] Cannot find YAML config at: {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def ask_ollama(prompt_text):
    """Send the rendered prompt to the local Ollama instance running llama3.2."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt_text,
        "stream": False
    }
    
    try:
        # High timeout because local LLMs can take time to generate full reports
        response = requests.post(OLLAMA_URL, json=payload, timeout=300)
        response.raise_for_status()
        data = response.json()
        return data.get("response", "").strip()
    except requests.exceptions.RequestException as e:
        print(f"[!] Ollama Connection Error: {e}")
        return "ERROR: Failed to generate report via LLM."

def main():
    print("[*] Initializing Intelligence Report Generator...")
    
    # 1. Load configurations and data
    try:
        candidates_data = load_json(CANDIDATES_FILE)
        module_config = load_yaml(YAML_FILE)
    except Exception as e:
        print(e)
        return

    global_settings = module_config.get("global_settings", {})
    categories_config = module_config.get("categories", {})

    # 2. Setup Jinja2 Environment
    env = Environment(loader=FileSystemLoader(J2_DIR), trim_blocks=True, lstrip_blocks=True)
    try:
        template = env.get_template(J2_TEMPLATE_NAME)
    except Exception as e:
        print(f"[!] Jinja2 Template Error: Cannot load {J2_TEMPLATE_NAME} from {J2_DIR}. {e}")
        return

    final_report = {}
    current_report_titles = {}

    # 3. Iterate over each category and topic to generate the report
    for category_name, topics in candidates_data.items():
        print(f"\n[*] Processing Category: {category_name.upper()}")
        final_report[category_name] = []
        current_report_titles[category_name] = []
        
        category_config = categories_config.get(category_name, {})
        
        for index, topic in enumerate(topics):
            topic_number = index + 1
            print(f"    -> Generating Topic {topic_number} ({topic.get('weighted_balance', 'unknown')} weight)...")
            
            # Save the title for the already_covered cache
            current_report_titles[category_name].append(topic.get("title", "No Title"))
            
            # Prepare data mapped exactly to what the Jinja2 template expects
            current_events = [{
                "id": topic.get("id", "Unknown"),
                "source_name": topic.get("source_name", "Unknown Source"),
                "title": topic.get("title", "No Title"),
                "description": topic.get("description", "No Description"),
                "breadcrumbs": ", ".join(topic.get("breadcrumbs", [])),
                "deep_dive_context": topic.get("deep_dive_context", "No Deep Dive Context")
            }]
            
            contextual_data = []
            supp_articles = topic.get("supplementary_articles", [])
            for supp in supp_articles:
                contextual_data.append({
                    "source_name": supp.get("source_name", "Unknown Source"),
                    "title": supp.get("title", "No Title"),
                    "description": supp.get("description", "No Description"),
                    "breadcrumbs": ", ".join(supp.get("breadcrumbs", []))
                })

            # Render the prompt
            prompt_text = template.render(
                global_settings=global_settings,
                category_name=category_name,
                category_config=category_config,
                current_events=current_events,
                contextual_data=contextual_data
            )

            # Generate narrative via LLM
            llm_narrative = ask_ollama(prompt_text)

            # Compile metadata for the output JSON
            sources = [f"{topic.get('source_name', 'Unknown Source')} ({topic.get('link', 'No Link')})"]
            for supp in supp_articles:
                sources.append(f"{supp.get('source_name', 'Unknown Source')} ({supp.get('link', 'No Link')})")
            
            # Consolidate all unique breadcrumbs
            all_breadcrumbs = set(topic.get("breadcrumbs", []))
            for supp in supp_articles:
                all_breadcrumbs.update(supp.get("breadcrumbs", []))

            # Build the finalized topic object
            finished_topic = {
                "topic_number": topic_number,
                "report": llm_narrative,
                "sources": list(sources),
                "breadcrumbs_used": list(all_breadcrumbs),
                "weighted_balance": topic.get("weighted_balance", "highpriority")
            }
            
            final_report[category_name].append(finished_topic)

    # 4. Save the assembled final report
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_report, f, indent=4)
        
    print(f"\n[+] Report Generation Complete! Saved to: {OUTPUT_FILE}")

    # 5. Update already_covered.json cache
    print("[*] Updating already_covered cache...")
    cache_data = []
    if os.path.exists(COVERED_CACHE_FILE):
        try:
            with open(COVERED_CACHE_FILE, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
        except json.JSONDecodeError:
            cache_data = []

    # Clean old entries (> 168 hours)
    now = datetime.now()
    cleaned_cache = []
    for entry in cache_data:
        entry_date_str = entry.get("report_date")
        if entry_date_str:
            try:
                entry_date = datetime.fromisoformat(entry_date_str)
                if now - entry_date <= timedelta(hours=168):
                    cleaned_cache.append(entry)
            except ValueError:
                pass  # Skip entries with invalid date formats

    # Append new entry
    cleaned_cache.append({
        "report_date": now.isoformat(),
        "report_truncated": current_report_titles
    })

    # Save cache
    os.makedirs(os.path.dirname(COVERED_CACHE_FILE), exist_ok=True)
    with open(COVERED_CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cleaned_cache, f, indent=4)
        
    print(f"[+] Cache updated and cleaned. Saved to: {COVERED_CACHE_FILE}")

if __name__ == "__main__":
    main()