import sqlite3
import json
import os
import re
import chromadb
from datetime import datetime, timedelta

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "parsed_data", "parsed_intel.sqlite"))

# ChromaDB Configuration - Adjust this path to where your chroma.sqlite3 lives
CHROMA_PATH = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "vector_db", "chroma.sqlite3"))
CHROMA_COLLECTION_NAME = "colections" # Change to your actual collection name

# Cache paths
TRENDS_FILE = os.path.join(SCRIPT_DIR, "cache", "top_trends.json")
FEEDS_FILE = os.path.join(SCRIPT_DIR, "cache", "feeds_results.json")
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "cache", "report_candidates.json")
OUTPUT_JSON_ALL = os.path.join(SCRIPT_DIR, "cache", "all_candidates.json")
EVAL_REPORT = os.path.join(SCRIPT_DIR, "cache", "all_candidates.txt")

# Target variables
TOPICS_PER_CATEGORY = 3
SUPPORTING_LINKS_NEEDED = 2

TARGET_CATEGORIES = [
    "threat_intelligence", 
    "general_news", 
    "org_pages", 
    "academic_research", 
    "community_pulse"
]

def load_json_file(filepath, default_type=dict):
    """Safely load a JSON file."""
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: Could not decode JSON from {filepath}.")
    else:
        print(f"Warning: File not found: {filepath}")
    return default_type()

def parse_breadcrumbs_column(b_str):
    """Safely parse the breadcrumbs column into a list of strings."""
    if not b_str:
        return []
    try:
        parsed = json.loads(b_str.replace("'", '"'))
        if isinstance(parsed, list):
            return [str(x).strip() for x in parsed]
    except Exception:
        pass
    return [x.strip() for x in b_str.split(',') if x.strip()]

def extract_cves(text):
    """Regex to find any CVE identifiers in text."""
    if not text:
        return []
    pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    return list(set([c.upper() for c in pattern.findall(text)]))

def get_latest_data_date(conn):
    """Finds the most recent date present in the raw_news table."""
    try:
        query = "SELECT MAX(published) as last_date FROM raw_news"
        row = conn.execute(query).fetchone()
        if row and row['last_date']:
            return datetime.strptime(row['last_date'], '%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"[!] Date parser error: {e}")
    return datetime.now()

def score_article(article, top_trends_dict, feeds_data):
    """Advanced Global Ranking System based on thresholds."""
    score = 0
    scoring_reasons = []
    highest_epss = 0.0
    is_kev = False
    
    search_text = " ".join(article['breadcrumbs']) + " " + str(article['title']) + " " + str(article['description'])
    cves_found = extract_cves(search_text)
    article['cves'] = cves_found
    
    # 1. Score based on CVEs (KEV + EPSS)
    for cve in cves_found:
        feed_info = feeds_data.get(cve, {})
        if feed_info.get('in_kev') is True:
            score += 50
            is_kev = True
            scoring_reasons.append(f"+50 (KEV: {cve})")
            
        epss = feed_info.get('epss_score', 0.0)
        if epss > highest_epss:
            highest_epss = epss

    if highest_epss > 0:
        epss_bonus = int(highest_epss * 25)
        score += epss_bonus
        scoring_reasons.append(f"+{epss_bonus} (EPSS: {highest_epss})")
        
    # 2. Score based on Top Trends
    max_surge_pct = 0
    for breadcrumb in article['breadcrumbs']:
        b_upper = breadcrumb.upper()
        surge_pct = top_trends_dict.get(b_upper, 0.0)
        if surge_pct > max_surge_pct:
            max_surge_pct = surge_pct
            
        if surge_pct > 150:
            score += 25
            scoring_reasons.append(f"+25 (Surge: {surge_pct}%)")
            break
            
    # 3. Baseline Scoring
    if score == 0:
        score = 10
        scoring_reasons.append("+10 (Recency)")
        
    article['score'] = score
    article['scoring_reasons'] = scoring_reasons
    article['metrics'] = {
        "is_kev": is_kev,
        "epss": highest_epss,
        "surge_pct": max_surge_pct
    }
    return article

def find_supplementary_articles(conn, main_article, used_urls, chroma_collection=None):
    """
    Finds contextual articles from anywhere in the timeline.
    Uses ChromaDB for Semantic/Vector Search if available, otherwise falls back to SQL tag matching.
    """
    supps = []
    
    # --- PREFERRED METHOD: Semantic Vector Search via ChromaDB ---
    if chroma_collection:
        try:
            # We query the vector space using the narrative essence of the article
            query_text = f"{main_article['title']}. {main_article['description']}"
            
            # Fetch more than we need to account for filtering (same source, already used)
            results = chroma_collection.query(
                query_texts=[query_text],
                n_results=15
            )
            
            # Assuming your Chroma IDs map exactly to your SQLite raw_news 'id'
            similar_ids = results['ids'][0]
            
            # Filter out the main article itself
            similar_ids = [sid for sid in similar_ids if str(sid) != str(main_article['id'])]
            
            if similar_ids:
                # Build SQL to grab the full row data for the closest semantic matches
                placeholders = ','.join(['?'] * len(similar_ids))
                query = f"""
                    SELECT id, title, link, source_name, description, raw_category, breadcrumbs, published
                    FROM raw_news
                    WHERE id IN ({placeholders})
                      AND source_name != ?
                    ORDER BY published DESC
                """
                params = similar_ids + [main_article['source_name']]
                
                cursor = conn.execute(query, params)
                for row in cursor:
                    url = row['link']
                    if url not in used_urls:
                        used_urls.add(url)
                        supps.append({
                            "id": row['id'],
                            "title": row['title'],
                            "link": url,
                            "source_name": row['source_name'],
                            "description": row['description'],
                            "raw_category": row['raw_category'],
                            "breadcrumbs": parse_breadcrumbs_column(row['breadcrumbs']),
                            "correlation_method": "semantic_vector_search"
                        })
                        
                        if len(supps) >= SUPPORTING_LINKS_NEEDED:
                            return supps # Early return if we hit our target via vector search
        except Exception as e:
            print(f"[!] ChromaDB Search Error: {e}. Falling back to SQL...")

    # Logic to fall back to the SQLite database in the event of an issue with the ChromaDB stuff
    breadcrumbs = main_article['breadcrumbs']
    if not breadcrumbs:
        return supps

    placeholders = ','.join(['?'] * len(breadcrumbs))
    query = f"""
        SELECT r.id, r.title, r.link, r.source_name, r.description, r.raw_category, r.breadcrumbs, r.published
        FROM raw_news r
        JOIN mapping_table m ON r.id = m.news_id
        JOIN breadcrumbs b ON m.breadcrumb_id = b.id
        WHERE b.breadcrumb IN ({placeholders})
          AND r.id != ? 
          AND r.source_name != ?
        GROUP BY r.id
        HAVING COUNT(DISTINCT b.breadcrumb) >= 3
        ORDER BY r.published DESC
        LIMIT 10
    """
    params = breadcrumbs + [main_article['id'], main_article['source_name']]
    
    try:
        cursor = conn.execute(query, params)
        for row in cursor:
            url = row['link']
            if url not in used_urls:
                used_urls.add(url)
                supps.append({
                    "id": row['id'],
                    "title": row['title'],
                    "link": url,
                    "source_name": row['source_name'],
                    "description": row['description'],
                    "raw_category": row['raw_category'],
                    "breadcrumbs": parse_breadcrumbs_column(row['breadcrumbs']),
                    "correlation_method": "sql_tag_fallback"
                })
                
                if len(supps) >= SUPPORTING_LINKS_NEEDED:
                    break
    except sqlite3.Error as e:
        print(f"[!] Supplementary search error: {e}")
        
    return supps

def generate_evaluation_report(all_candidates):
    """Creates a human-readable text file showing the math behind choices."""
    os.makedirs(os.path.dirname(EVAL_REPORT), exist_ok=True)
    with open(EVAL_REPORT, 'w', encoding='utf-8') as f:
        f.write("=== ALGORITHM SELECTION EVALUATION ===\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for i, article in enumerate(all_candidates, 1):
            f.write(f"{i}. {article['title']}\n")
            f.write(f"   Category: {article['raw_category']} | Source: {article['source_name']}\n")
            f.write(f"   Score:    {article['score']}\n")
            f.write(f"   Math:     {', '.join(article['scoring_reasons'])}\n")
            f.write(f"   Link:     {article['link']}\n\n")

def generate_report():
    print("[*] Starting Topic Selection Engine...")
    
    # Initialize Vector DB (Chroma)
    chroma_collection = None
    try:
        if os.path.exists(CHROMA_PATH):
            print("[*] Initializing neural databanks (ChromaDB)...")
            chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
            chroma_collection = chroma_client.get_collection(name=CHROMA_COLLECTION_NAME)
        else:
            print("[!] ChromaDB not found at path. Relying on standard SQL protocols.")
    except Exception as e:
        print(f"[!] Failed to initialize ChromaDB: {e}")

    # 1. Load context data
    feeds_data = load_json_file(FEEDS_FILE, dict)
    trends_data = load_json_file(TRENDS_FILE, list)
    
    top_trends_dict = {
        t['breadcrumb'].upper(): t.get('surge_pct', 0.0) 
        for t in trends_data if 'breadcrumb' in t
    }

    # 2. Fetch recent data from SQLite (48-Hour Logic)
    if not os.path.exists(DB_PATH):
        print(f"[!] Error: Database not found at {DB_PATH}")
        return

    all_articles = []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        
        latest_date = get_latest_data_date(conn)
        cutoff_date = latest_date - timedelta(hours=48)
        cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"[*] Analyzing data from: {cutoff_str} to {latest_date.strftime('%Y-%m-%d %H:%M:%S')}")
        
        query = """
            SELECT id, published, raw_category, source_name, title, link, description, breadcrumbs
            FROM raw_news
            WHERE published >= ?
        """
        cursor = conn.execute(query, (cutoff_str,))
        rows = cursor.fetchall()
        
        # 3. Process and score each article
        for row in rows:
            article = {
                "id": row["id"],
                "published": row["published"],
                "raw_category": row["raw_category"],
                "source_name": row["source_name"],
                "title": row["title"],
                "link": row["link"],
                "description": row["description"],
                "breadcrumbs": parse_breadcrumbs_column(row["breadcrumbs"])
            }
            
            # Apply thresholds scoring algorithm
            article = score_article(article, top_trends_dict, feeds_data)
            all_articles.append(article)
            
    except sqlite3.Error as e:
        print(f"[!] Database error: {e}")
        if conn: conn.close()
        return

    # Sort all articles descending by their calculated score
    all_articles.sort(key=lambda x: x['score'], reverse=True)
    
    # 4. Save the top 100 overall candidates (Matches the info in .txt)
    top_100_candidates = all_articles[:100]
    os.makedirs(os.path.dirname(OUTPUT_JSON_ALL), exist_ok=True)
    with open(OUTPUT_JSON_ALL, 'w', encoding='utf-8') as f:
        json.dump(top_100_candidates, f, indent=4)
        
    generate_evaluation_report(top_100_candidates)
    print(f"[*] Saved Top 100 candidates to {OUTPUT_JSON_ALL} and {EVAL_REPORT}")

    # --- 5. Build the category-based report with Novelty vs. Severity Balance ---
    report_chosen = {category: [] for category in TARGET_CATEGORIES}
    used_urls = set()          # Track chosen URLs globally
    used_breadcrumbs = set()   # Track used breadcrumbs globally (lowercase)
    last_novelty_category = None
    
    # Load Novelty Candidate Breadcrumbs
    novelty_breadcrumbs_list = []
    try:
        novelty_query = """
            SELECT breadcrumb, category 
            FROM breadcrumbs 
            WHERE confidence_score > 0.90 AND count > 0 
            ORDER BY count ASC
        """
        novelty_cursor = conn.execute(novelty_query)
        novelty_breadcrumbs_list = [{"breadcrumb": r["breadcrumb"], "category": r["category"]} for r in novelty_cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"[!] Novelty breadcrumbs table error: {e}")

    for category in TARGET_CATEGORIES:
        # Get unused articles for this category
        cat_articles = [a for a in all_articles if a['raw_category'] == category and a['link'] not in used_urls]
        category_chosen = []
        
        # --- Slot 1: High Priority (Severity Anchor) ---
        if cat_articles:
            hp_article = cat_articles.pop(0) # Grabs the highest scored remaining article
            hp_article['weighted_balance'] = 'highpriority'
            category_chosen.append(hp_article)
            
            used_urls.add(hp_article['link'])
            for b in hp_article['breadcrumbs']:
                used_breadcrumbs.add(b.lower())

        # --- Slots 2 & 3: Novelty ---
        novelty_needed = TOPICS_PER_CATEGORY - len(category_chosen)
        
        for _ in range(novelty_needed):
            novelty_found = False
            for nb in novelty_breadcrumbs_list:
                nb_name_lower = nb['breadcrumb'].lower()
                nb_cat = nb['category']
                
                # Enforce Diversity Constraints
                if nb_name_lower in used_breadcrumbs:
                    continue
                if nb_cat == last_novelty_category:
                    continue
                    
                # Search for an available article matching this novelty breadcrumb
                for i, a in enumerate(cat_articles):
                    a_breadcrumbs_lower = [b.lower() for b in a['breadcrumbs']]
                    if nb_name_lower in a_breadcrumbs_lower:
                        nov_article = cat_articles.pop(i)
                        nov_article['weighted_balance'] = 'novelty'
                        category_chosen.append(nov_article)
                        
                        used_urls.add(nov_article['link'])
                        for b in nov_article['breadcrumbs']:
                            used_breadcrumbs.add(b.lower())
                            
                        last_novelty_category = nb_cat
                        novelty_found = True
                        break # Break internal article search
                        
                if novelty_found:
                    break # Move to the next slot once a novelty article is found
            
            # --- Fallback: Back to High Priority if no novelty criteria matches ---
            if not novelty_found and cat_articles:
                fb_article = cat_articles.pop(0)
                fb_article['weighted_balance'] = 'highpriority'
                category_chosen.append(fb_article)
                
                used_urls.add(fb_article['link'])
                for b in fb_article['breadcrumbs']:
                    used_breadcrumbs.add(b.lower())

        # Process supplementary articles for the chosen top 3 in this category
        for article in category_chosen:
            supps = find_supplementary_articles(conn, article, used_urls, chroma_collection)
            for s in supps:
                # Burn supplementary breadcrumbs to keep the next report sections fresh
                for b in s['breadcrumbs']:
                    used_breadcrumbs.add(b.lower())
                    
            article["supplementary_articles"] = supps
            report_chosen[category].append(article)

    # 6. Save the final report candidates
    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(report_chosen, f, indent=4)
        
    print(f"[+] Process complete. Final Output: {OUTPUT_JSON}")
    conn.close()

if __name__ == "__main__":
    generate_report()