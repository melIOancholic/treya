import os
import re
import sys
import json
import sqlite3
import datetime
import warnings
import logging
from dotenv import load_dotenv

# --- ADDED: Fix for Windows 'charmap' UnicodeEncodeError ---
# Forces standard output to handle complex characters (like emojis or foreign languages)
# without throwing the 'charmap' UnicodeEncodeError during print() or log_callback().
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
# -----------------------------------------------------------

import inflect
import nvdlib
from pyattck import Attck
from msticpy.sectools import IoCExtract
import geonamescache
from gliner import GLiNER
from cwe2.database import Database

# --- New Data Engineering Imports ---
import pandas as pd
import numpy as np
import chromadb
from chromadb.utils import embedding_functions

warnings.filterwarnings("ignore", category=UserWarning, message=".*truncated.*")

# Silence the 'httpx' library used for API requests
logging.getLogger("httpx").setLevel(logging.WARNING)
# Silence the 'huggingface_hub' library used for model downloads
logging.getLogger("huggingface_hub").setLevel(logging.WARNING)

# Attempt to load MSTICPy lookups (Need to configure msticpyconfig.yaml locally)
msticpy_startup_error = None
try:
    from msticpy.sectools.tilookup import TILookup
    from msticpy.sectools.geoip import GeoLiteLookup
    MST_TI = TILookup()
    MST_GEO = GeoLiteLookup()
except Exception as e:
    msticpy_startup_error = f"[*] MSTICPy Lookups disabled or missing config (IoCExtract will still run): {e}"
    MST_TI = None
    MST_GEO = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_DB_PATH = os.path.join(BASE_DIR, "parsed_data", "parsed_intel.sqlite")
VECTOR_DB_PATH = os.path.join(BASE_DIR, "vector_db") # Folder for ChromaDB

# Load key from .env file
dotenv_path = os.path.join(BASE_DIR, "enrichment", ".env")
load_dotenv(dotenv_path)

print(f"DEBUG: NVD Key Loaded: {'Yes' if os.getenv('NVD_API_KEY') else 'No'}")
print(f"DEBUG: Searching for .env at: {dotenv_path}")

# Mappings to strictly enforce your 8 required categories
CATEGORY_MAP = {
    "vulnerabilities": "vulnerability",
    "threat_actors": "threat_actor",
    "quantum": "tech",
    "hardware": "tech",
    "software": "tech",
    "geodata": "geodata",
    "attack_vector": "attack_vector",
    "entity": "entity",
    "operation": "operation",
    "malware": "malware",
    "tech": "tech"
}

class IntelligenceBrain:
    def __init__(self, nvd_api_key=None, log_callback=print):
        self.log_callback = log_callback
        self.nvd_key = nvd_api_key or os.getenv("NVD_API_KEY")
        self.p = inflect.engine()
        self.cwe_db = Database()
        
        # --- CHROMADB SETUP (Vector Store) ---
        self.log_callback("[*] Initializing ChromaDB persistent client...")
        os.makedirs(VECTOR_DB_PATH, exist_ok=True)
        self.chroma_client = chromadb.PersistentClient(path=VECTOR_DB_PATH)
        # Using a lightweight, fast sentence transformer for local processing
        self.embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        self.collection = self.chroma_client.get_or_create_collection(
            name="news_vectors",
            embedding_function=self.embed_fn
        )
        
        # --- PHASE 1 DATA: Hardcoded Lists (High Confidence) ---
        self.attacks_high = {
            "AI/ML": [
                "Prompt Injection", "Indirect Prompt Injection", "Jailbreaking", "Adversarial Attack", 
                "Data Poisoning", "Model Inversion", "Model Evasion", "Prompt Leakage", "Extraction Attack", 
                "Membership Inference", "Backdoor Attack", "Token Smuggling", "Gradient Leakage", "Sybil Attack"
            ],
            "Web": [
                "XSS", "Cross-Site Scripting", "SQL Injection", "SQLi", "CSRF", "Cross-Site Request Forgery", 
                "SSRF", "Server-Side Request Forgery", "XXE", "XML External Entity", "Path Traversal", 
                "Directory Traversal", "Command Injection", "Remote Code Execution", "RCE", 
                "Insecure Deserialization", "Broken Access Control", "Clickjacking", "Session Hijacking"
            ],
            "Network": [
                "DDoS", "Distributed Denial of Service", "Man-in-the-Middle", "MitM", "DNS Spoofing", 
                "DNS Tunneling", "BGP Hijacking", "ARP Poisoning", "Packet Sniffing", "Port Scanning", 
                "IP Spoofing", "Brute Force", "Credential Stuffing", "Password Spraying", "Replay Attack", "Evil Twin"
            ],
            "Social Engineering": [
                "Phishing", "Spear Phishing", "Whaling", "Smishing", "Vishing", "Business Email Compromise", 
                "BEC", "Pretexting", "Baiting", "Quid Pro Quo", "Tailgating", "Honeytrap", "Social Engineering", 
                "Deepfake Impersonation", "Scareware", "ClickFix" 
            ],
            "Malware": [
                "Ransomware", "Trojan Horse", "Worm", "Spyware", "Keylogger", "Rootkit", "Botnet", 
                "Cryptojacking", "Fileless Malware", "Adware", "Backdoor", "Zero-Day Exploit", "Logic Bomb", 
                "Malvertising", "Exploit Kit", "SloppyMIO", "Blackmoon", "KrBanker", "Banbra",
                "RAT", "Remote Access Trojan", "C2", "Command and Control", "Infostealer", "Information Stealer"
            ],
            "Supply Chain": [
                "Supply Chain Attack", "Vendor Compromise", "Software Update Poisoning", "Hardware Trojan", 
                "USB Drop", "Juice Jacking", "Dumpster Diving", "Skimming", "Side-Channel Attack", "Cold Boot Attack"
            ]
        }

        self.quantum_tech_high = {
            "Google Willow", "IBM Condor", "Qiskit Runtime", "cuQuantum", "Advantage2", "IonQ"
        }

        self.synonyms = {
            "RCE": "REMOTE CODE EXECUTION", "XSS": "CROSS-SITE SCRIPTING", "SQLI": "SQL INJECTION",
            "CSRF": "CROSS-SITE REQUEST FORGERY", "SSRF": "SERVER-SIDE REQUEST FORGERY",
            "XXE": "XML EXTERNAL ENTITY", "DDOS": "DISTRIBUTED DENIAL OF SERVICE",
            "MITM": "MAN-IN-THE-MIDDLE", "BEC": "BUSINESS EMAIL COMPROMISE",
            "WINRAR": "WINRAR ARCHIVER", "RAT": "REMOTE ACCESS TROJAN",
            "C2": "COMMAND AND CONTROL", "INFOSTEALER": "INFORMATION STEALER"
        }

        self.flat_attacks = {}
        for cat, attacks in self.attacks_high.items():
            for a in attacks:
                self.flat_attacks[a.lower()] = cat
        
        self.flat_quantum = {q.lower(): "Quantum Computing" for q in self.quantum_tech_high}

        # --- PHASE 2 DATA: Libraries (Medium) ---
        try:
            self.attack_data = Attck(nested_subtechniques=False) 
            self.enterprise_attack = self.attack_data.enterprise
        except:
            self.enterprise_attack = None
            
        self.ioc_extractor = IoCExtract()
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        self.cwe_pattern = re.compile(r'CWE-\d+', re.IGNORECASE)

        # --- PHASE 3 DATA: Locations (High) ---
        self.locations_high = {
            "United States", "China", "United Kingdom", "Germany", "France", "Russia", "Ukraine", 
            "Israel", "North Korea", "Iran", "Taiwan", "Singapore", "India", "Estonia", "South Korea", 
            "Japan", "United Arab Emirates", "Canada", "Brazil", "Australia", "Netherlands", "Poland", 
            "Saudi Arabia", "Switzerland", "Vietnam", "Indonesia", "Mexico", "South Africa", "Turkey", 
            "Egypt", "Ireland", "Norway", "Argentina", "Philippines", "Nigeria", "Pakistan"
        }
        self.locations_high_lower = {loc.lower(): loc for loc in self.locations_high}

        # --- PHASE 4 DATA: Geonamescache (Medium) ---
        self.gc = geonamescache.GeonamesCache()
        self.us_states = self.gc.get_us_states()
        self.us_states_names = {v['name'].upper(): "United States" for k, v in self.us_states.items()}

        # --- PHASE 5 TOOL: GLiNER ---
        try:
            self.gliner_model = GLiNER.from_pretrained("urchade/gliner_small-v2.1")
        except Exception as e:
            self.log_callback(f"Warning: GLiNER could not be loaded: {e}")
            self.gliner_model = None

        self.gliner_labels = [
            "entity", "attack vector", "tech", "malware", 
            "vulnerability", "threat actor", "operation", "geodata"
        ]

    def normalize_breadcrumb(self, text):
        clean_text = text.strip()
        clean_text = re.sub(r'(?i)^(the|a|an)\s+', '', clean_text)
        singular = self.p.singular_noun(clean_text)
        if singular:
            clean_text = singular
        upper_text = clean_text.upper()
        return self.synonyms.get(upper_text, upper_text)

    def extract_initial_breadcrumbs(self, text):
        """Phase 1: Identification & Extraction (Creates the core dict per row)"""
        # Note: Your original scoring and logic is 100% untouched here!
        breadcrumbs = {} 
        text_lower = text.lower()

        # === Hardcoded Lists ===
        for attack_name, category_parent in self.flat_attacks.items():
            if attack_name in text_lower:
                normalized_name = self.normalize_breadcrumb(attack_name)
                cat = "malware" if category_parent == "Malware" else "attack_vector"
                if normalized_name not in breadcrumbs:
                    breadcrumbs[normalized_name] = {
                        "breadcrumb": normalized_name, "category": cat, 
                        "confidence": "high", "confidence_score": 0.90, "enriched_by": "predefined"
                    }

        for tech_name, category_parent in self.flat_quantum.items():
            if tech_name in text_lower:
                normalized_name = tech_name.upper()
                if normalized_name not in breadcrumbs:
                    breadcrumbs[normalized_name] = {
                        "breadcrumb": normalized_name, "category": "tech",
                        "confidence": "high", "confidence_score": 0.90, "enriched_by": "predefined"
                    }

        # === Regex/Libraries ===
        cves = self.cve_pattern.findall(text)
        for cve in cves:
            normalized_cve = cve.upper()
            if normalized_cve not in breadcrumbs:
                breadcrumbs[normalized_cve] = {
                    "breadcrumb": normalized_cve, "category": "vulnerability", 
                    "confidence": "high", "confidence_score": 0.80, "enriched_by": "NVDlib"
                }

        cwes = self.cwe_pattern.findall(text)
        for cwe in cwes:
            normalized_cwe = cwe.upper()
            if normalized_cwe not in breadcrumbs:
                breadcrumbs[normalized_cwe] = {
                    "breadcrumb": normalized_cwe, "category": "vulnerability", 
                    "confidence": "high", "confidence_score": 0.80, "enriched_by": "NVDlib"
                }

        if self.enterprise_attack:
            for actor in self.enterprise_attack.actors:
                if actor.name.lower() in text_lower:
                    normalized_actor = actor.name.upper()
                    if normalized_actor not in breadcrumbs:
                        breadcrumbs[normalized_actor] = {
                            "breadcrumb": normalized_actor, "category": "threat_actor", 
                            "confidence": "medium", "confidence_score": 0.80, "enriched_by": "PyAttck"
                        }

        # === Locations ===
        for loc_lower, loc_original in self.locations_high_lower.items():
            if loc_lower in text_lower:
                normalized_loc = loc_original.upper()
                if normalized_loc not in breadcrumbs:
                    breadcrumbs[normalized_loc] = {
                        "breadcrumb": normalized_loc, "category": "geodata", 
                        "confidence": "high", "confidence_score": 0.90, "enriched_by": "predefined"
                    }

        for state_upper, country in self.us_states_names.items():
            if state_upper.lower() in text_lower:
                if state_upper not in breadcrumbs:
                    breadcrumbs[state_upper] = {
                        "breadcrumb": state_upper, "category": "geodata", 
                        "confidence": "high", "confidence_score": 0.70, "enriched_by": "Geonamescache"
                    }

        # === GLiNER ===
        if self.gliner_model:
            entities = self.gliner_model.predict_entities(text, self.gliner_labels, threshold=0.3)
            for ent in entities:
                ent_text = ent["text"]
                ent_label = ent["label"]
                ent_score = round(ent.get("score", 0), 2)
                
                if ent_score < 0.40:
                    continue
                    
                new_confidence = "high" if ent_score >= 0.89 else ("medium" if 0.75 <= ent_score <= 0.88 else "low")
                
                if ent_label in ["city", "country", "state"]:
                    normalized_ent = ent_text.upper()
                else:
                    normalized_ent = self.normalize_breadcrumb(ent_text)

                if normalized_ent in breadcrumbs:
                    continue
                    
                if ent_label in ["city", "country", "state"]:
                    if ent_label == "city" and not self.gc.get_cities_by_name(ent_text):
                        continue # Invalid geo
                    category = "geodata"
                else:
                    category = "tech"
                    if ent_label in ["organization", "security team"]: category = "entity"
                    elif ent_label == "hardware": category = "tech"
                    elif ent_label in ["software", "mobile app", "database", "operating system"]: category = "tech"
                    elif ent_label in ["malware", "vulnerability", "cyber attack"]: category = "attack_vector"
                    elif ent_label in ["threat actor", "cyber campaign", "operation"]: category = "threat_actor"
                    elif ent_label == "quantum technology": category = "tech"

                breadcrumbs[normalized_ent] = {
                    "breadcrumb": normalized_ent, "category": CATEGORY_MAP.get(category, category),
                    "confidence": new_confidence, "confidence_score": ent_score, "enriched_by": "GLiNER"
                }

        return list(breadcrumbs.values())

    def deep_enrich(self, breadcrumb_data):
        """Phase 3: Comprehensive LLM-Readable Context Enrichment"""
        term = breadcrumb_data["breadcrumb"]
        category = breadcrumb_data["category"]
        context_pairs = []

        # 1. NVDlib Enrichment (ONLY for CVEs)
        if category == "vulnerability" and term.startswith("CVE-"):
            try:
                r = nvdlib.searchCVE(cveId=term, key=self.nvd_key, delay=0.6) if self.nvd_key else nvdlib.searchCVE(cveId=term, delay=1)
                if r:
                    cve = r[0]
                    if hasattr(cve, 'descriptions') and len(cve.descriptions) > 0:
                        description = next((d.value for d in cve.descriptions if d.lang == 'en'), cve.descriptions[0].value)
                        context_pairs.append(f"description: {description}")
                    if hasattr(cve, 'metrics') and hasattr(cve.metrics, 'cvssMetricV31'):
                        context_pairs.append(f"v31score: {cve.metrics.cvssMetricV31[0].cvssData.baseScore}")
                        context_pairs.append(f"v31severity: {cve.metrics.cvssMetricV31[0].cvssData.baseSeverity}")
                    context_pairs.append(f"published: {cve.published}")
                    if hasattr(cve, 'lastModified'):
                        context_pairs.append(f"last_modified: {cve.lastModified}")
                    if hasattr(cve, 'weaknesses'):
                        weaks = [w.description[0].value for w in cve.weaknesses]
                        context_pairs.append(f"weaknesses: {' | '.join(weaks)}")
                    if hasattr(cve, 'cisaExploitAdd'):
                        context_pairs.append(f"exploitAdd: {cve.cisaExploitAdd}")
            except Exception as e:
                context_pairs.append(f"nvd_error: {str(e)}")

        # 1.5 cwe2 Enrichment for CWEs
        elif category == "vulnerability" and term.startswith("CWE-"):
            try:
                cwe_id_str = term.replace("CWE-", "")
                cwe_obj = self.cwe_db.get(cwe_id_str)
                if cwe_obj:
                    if hasattr(cwe_obj, 'description'):
                        context_pairs.append(f"description: {cwe_obj.description}")
                    if hasattr(cwe_obj, 'potential_mitigations'):
                        mits = cwe_obj.potential_mitigations
                        context_pairs.append(f"potential_mitigations: {str(mits)}")
            except Exception as e:
                context_pairs.append(f"cwe2_error: {str(e)}")

        # 2. PyAttck Enrichment
        if self.enterprise_attack and category in ["threat_actor", "attack_vector", "malware"]:
            search_term = term.lower()
            # Check Actors
            for actor in self.enterprise_attack.actors:
                if search_term in actor.name.lower():
                    if hasattr(actor, 'aliases') and actor.aliases:
                        aliases = [a for a in actor.aliases if a.lower() != actor.name.lower()]
                        if aliases: context_pairs.append(f"known_aliases: {' | '.join(aliases)}")
                    if hasattr(actor, 'tactics'):
                        tactics = [t.name for t in actor.tactics][:5]
                        if tactics: context_pairs.append(f"tactics: {' | '.join(tactics)}")
                    if hasattr(actor, 'techniques'):
                        techs = [t.name for t in actor.techniques][:5]
                        if techs: context_pairs.append(f"techniques: {' | '.join(techs)}")
                    break
            
            # Check Techniques/Attack Vectors
            for tech in self.enterprise_attack.techniques:
                if search_term in tech.name.lower():
                    if hasattr(tech, 'tactics'):
                        tactics = [t.name for t in tech.tactics]
                        if tactics: context_pairs.append(f"tactics: {' | '.join(tactics)}")
                    if hasattr(tech, 'subtechniques'):
                        subtechs = [s.name for s in tech.subtechniques][:5]
                        if subtechs: context_pairs.append(f"subtechniques: {' | '.join(subtechs)}")
                    if hasattr(tech, 'mitigations'):
                        controls = [m.name for m in tech.mitigations][:5]
                        if controls: context_pairs.append(f"suggested_controls: {' | '.join(controls)}")
                    break

        # 3. MSTICPy Enrichment
        try:
            ioc_results = self.ioc_extractor.extract(term)
            if ioc_results:
                ioc_types = list(ioc_results.keys())
                context_pairs.append(f"msticpy_ioc_type: {' | '.join(ioc_types)}")
                if "ipv4" in ioc_types or "dns" in ioc_types:
                    if MST_GEO:
                        geo_res = MST_GEO.lookup_ip(term)
                        if not geo_res.empty:
                            country = geo_res.iloc[0].get("CountryCode", "Unknown")
                            context_pairs.append(f"geolite_country: {country}")
                    if MST_TI:
                        ti_res = MST_TI.lookup_ioc(term)
                        if not ti_res.empty:
                            sev = ti_res.iloc[0].get("Severity", "Unknown")
                            context_pairs.append(f"ti_severity: {sev}")
        except Exception:
            pass 

        # 4. Geonamescache Enrichment
        if category == "geodata":
            cities = self.gc.get_cities_by_name(term)
            if cities:
                city_data = list(cities[0].values())[0]
                context_pairs.append(f"latitude: {city_data.get('latitude')}")
                context_pairs.append(f"longitude: {city_data.get('longitude')}")
                context_pairs.append(f"population: {city_data.get('population')}")
                context_pairs.append(f"timezone: {city_data.get('timezone')}")
            else:
                countries = self.gc.get_countries_by_names()
                if term.title() in countries:
                    c_data = countries[term.title()]
                    context_pairs.append(f"capital: {c_data.get('capital')}")
                    context_pairs.append(f"continent: {c_data.get('continentcode')}")
                    context_pairs.append(f"iso_alpha3: {c_data.get('iso3')}")

        if not context_pairs:
            context_pairs.append("status: no_additional_context_found")
        return ", ".join(context_pairs)

def setup_database():
    """Ensure database tables and columns exist."""
    os.makedirs(os.path.dirname(SQLITE_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(SQLITE_DB_PATH)
    c = conn.cursor()
    
    c.execute("DROP TABLE IF EXISTS breadcrumbs")
    c.execute("DROP TABLE IF EXISTS mapping_table")
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS raw_news (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            published TEXT, 
            crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            raw_category TEXT, 
            source_name TEXT, 
            title TEXT, 
            link TEXT UNIQUE, 
            description TEXT
        )
    """)
    
    try:
        c.execute("ALTER TABLE raw_news ADD COLUMN breadcrumbs TEXT")
    except sqlite3.OperationalError:
        pass 
        
    c.execute("""
        CREATE TABLE IF NOT EXISTS breadcrumbs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            breadcrumb TEXT UNIQUE,
            category TEXT,
            count INTEGER,
            confidence TEXT,
            confidence_score REAL,
            enriched_by TEXT,
            context TEXT
        )
    """)
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS mapping_table (
            breadcrumb_id INTEGER,
            news_id INTEGER,
            FOREIGN KEY(breadcrumb_id) REFERENCES breadcrumbs(id),
            FOREIGN KEY(news_id) REFERENCES raw_news(id)
        )
    """)
        
    conn.commit()
    return conn

def main(log_callback=print):
    if msticpy_startup_error:
        log_callback(msticpy_startup_error)

    log_callback("[*] Initializing Intelligence Brain and connecting to DB...")
    brain = IntelligenceBrain(log_callback=log_callback)
    conn = setup_database()
    
    # ---------------------------------------------------------
    # --- PANDAS VECTORIZATION PIPELINE START ---
    # ---------------------------------------------------------
    log_callback("[*] Reading 'raw_news' into Pandas DataFrame...")
    
    # 1. Load data directly into a Pandas DataFrame
    df = pd.read_sql_query("SELECT id, title, description, source_name, published FROM raw_news", conn)
    
    if df.empty:
        log_callback("[!] No data in raw_news table. Exiting.")
        conn.close()
        return

    # Fill empty strings instead of dealing with None/NULL
    df['title'] = df['title'].fillna('')
    df['description'] = df['description'].fillna('')
    df['text_corpus'] = df['title'] + ". " + df['description']

    # --- CHROMADB UPSERT (The Vector Addition) ---
    log_callback("[*] Embedding articles into ChromaDB...")
    try:
        # We send the entire column to ChromaDB at once
        documents = df['text_corpus'].tolist()
        metadatas = df.apply(lambda row: {"source": row['source_name'], "published": str(row['published'])}, axis=1).tolist()
        ids = df['id'].astype(str).tolist()
        
        brain.collection.upsert(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        log_callback(f"[*] Successfully saved {len(documents)} vectors to ChromaDB.")
    except Exception as e:
        log_callback(f"[!] Warning: ChromaDB upsert failed: {e}")

    # --- PANDAS VECTORIZED EXTRACTION ---
    log_callback("[*] Using Pandas to extract breadcrumbs across all articles. This part always takes a while...")
    # This runs your existing algorithm on every row
    df['extracted_entities'] = df['text_corpus'].apply(brain.extract_initial_breadcrumbs)

    # Convert the nested list of dictionaries into a clean, flat table
    df_exploded = df.explode('extracted_entities').dropna(subset=['extracted_entities'])
    
    if df_exploded.empty:
        log_callback("[!] No breadcrumbs found in any articles.")
        conn.close()
        return
        
    # Expand the dictionary keys into actual Pandas columns
    df_entities = pd.json_normalize(df_exploded['extracted_entities'])
    # Attach the original news IDs and source names to our new flat table
    df_entities['news_id'] = df_exploded['id'].values
    df_entities['source_name'] = df_exploded['source_name'].values

    # --- UPDATE RAW_NEWS TALE ---
    log_callback("[*] Mapping breadcrumbs back to 'raw_news'...")
    # Group by news_id and combine the names into a comma-separated string
    news_breadcrumbs = df_entities.groupby('news_id')['breadcrumb'].apply(lambda x: ", ".join(x)).reset_index()
    
    c = conn.cursor()
    # Batch update the raw_news table
    update_data = list(zip(news_breadcrumbs['breadcrumb'], news_breadcrumbs['news_id']))
    c.executemany("UPDATE raw_news SET breadcrumbs = ? WHERE id = ?", update_data)
    conn.commit()

    # --- GROUP & DEDUPLICATE (Replaces the global_breadcrumbs logic) ---
    log_callback("[*] Deduplicating and tracking unique sources...")
    
    # Pandas Groupby instantly aggregates our data exactly like your old code did, but faster.
    grouped_breadcrumbs = df_entities.groupby('breadcrumb').agg({
        'category': 'first',
        'confidence': 'first',
        'confidence_score': 'first',
        'enriched_by': 'first',
        'source_name': lambda x: set(x), # Gets unique sources
        'news_id': lambda x: list(set(x)) # Gets unique article IDs
    }).reset_index()

    log_callback(f"[*] Extraction complete. {len(grouped_breadcrumbs)} unique breadcrumbs found.")
    log_callback("[*] Beginning Deep Enrichment Process (This may take a moment based on API/Library latency)...")

    # Phase 2 & 3: Enrich and Add to new 'breadcrumbs' table
    # We still loop here because APIs (like NVD) have rate limits and can't be purely vectorized
    total_breadcrumbs = len(grouped_breadcrumbs)
    for i, row in enumerate(grouped_breadcrumbs.itertuples(), 1):
        # Update dynamically on one line in the cmd
        print(f"\r[*] Processing breadcrumb {i}/{total_breadcrumbs}: {str(row.breadcrumb)[:50]:<50}", end="", flush=True)
        
        # Using Pandas logic to get the count
        occurrence_count = len(row.source_name) 
        
        # Prepare the dictionary for your existing deep_enrich function
        data_dict = {
            "breadcrumb": row.breadcrumb,
            "category": row.category
        }
        
        enriched_context_str = brain.deep_enrich(data_dict)

        # Upsert the breadcrumb into the isolated table
        c.execute("""
            INSERT INTO breadcrumbs (breadcrumb, category, count, confidence, confidence_score, context, enriched_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(breadcrumb) DO UPDATE SET 
                count = excluded.count,
                context = excluded.context
        """, (
            row.breadcrumb, 
            CATEGORY_MAP.get(row.category, row.category), 
            occurrence_count, 
            row.confidence, 
            row.confidence_score, 
            enriched_context_str, 
            row.enriched_by
        ))
        
        # Map the IDs in the mapping_table
        c.execute("SELECT id FROM breadcrumbs WHERE breadcrumb = ?", (row.breadcrumb,))
        breadcrumb_record = c.fetchone()
        
        if breadcrumb_record:
            breadcrumb_id = breadcrumb_record[0]
            # Use Pandas list of news_ids for batch inserting to the mapping table
            mapping_data = [(breadcrumb_id, int(n_id)) for n_id in row.news_id]
            c.executemany("INSERT INTO mapping_table (breadcrumb_id, news_id) VALUES (?, ?)", mapping_data)

    print() # Add a newline when the loop finishes to preserve the last dynamic output
    conn.commit()
    conn.close()
    log_callback("[*] Pipeline execution successful. All breadcrumbs extracted, deduplicated, enriched, vectorized, and stored.")

if __name__ == "__main__":
    main()