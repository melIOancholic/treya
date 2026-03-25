import yaml
import feedparser
import json
import time
import re
import requests
import ssl
import sqlite3
import os
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

# This file grabs and parses the information, and cleans and organizes it into a SQLite database.

# This line tells Python to create a "relaxed" SSL context 
# to prevent the 'Handshake Error'.
if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

def clean_html(raw_html):
    """
    Removes HTML tags and cleans up whitespace to make 
    the text human-readable. Also replaces fancy Unicode
    characters with standard ASCII equivalents.
    """
    if not raw_html:
        return ""
    
    soup = BeautifulSoup(raw_html, "html.parser")
    text = soup.get_text(separator=' ')
    
    replacements = {
        "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"',
        "\u2013": "-", "\u2014": "-",
        "\u00a0": " ", "\u00c9": "é"
    }
    
    for fancy, standard in replacements.items():
        text = text.replace(fancy, standard)
    
    clean_text = re.sub(r'\s+', ' ', text).strip()
    return clean_text

def init_db():
    """
    Initializes the SQLite database and creates the table if it doesn't exist.
    """
    # Ensure the directory exists
    os.makedirs('intel/parsed_data', exist_ok=True)
    
    db_path = 'intel/parsed_data/parsed_intel.sqlite'
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Create table with a UNIQUE constraint on the 'link' to prevent duplicates
    c.execute('''
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
    ''')
    conn.commit()
    return conn

def fetch_all_intel(callback=None):
    """
    Master function that loops through ALL categories.
    Handles RSS and specific Reddit JSON parsing logic.
    """
    
    def log(message):
        if callback:
            callback(message)
        else:
            print(message)

    # 1. SETUP
    HOURS_THRESHOLD_RSS = 168
    HOURS_THRESHOLD_JSON = 24
    
    current_time = datetime.now()
    rss_threshold_date = current_time - timedelta(hours=HOURS_THRESHOLD_RSS)
    json_threshold_date = current_time - timedelta(hours=HOURS_THRESHOLD_JSON)
    
    all_collected_articles = []

    # 2. LOAD YAML
    try:
        with open('intel/sources/sources.yaml', 'r') as file:
            config = yaml.safe_load(file)
    except FileNotFoundError:
        log("Ran into an error: sources.yaml not found.")
        return
    except Exception as e:
        log(f"Error reading the YAML: {e}")
        return

    # 3. DYNAMICALLY LOOP THROUGH CATEGORIES
    intel_sources = config.get('intel_sources', {})

    for raw_category_name, raw_category_data in intel_sources.items():
        feeds = raw_category_data.get('feeds', [])
        log(f"--- Starting fetch for {raw_category_name} ({len(feeds)} sources) ---")

        for feed_info in feeds:
            source_type = feed_info.get('type', 'rss').lower()
            log(f"Processing ({source_type}): {feed_info['name']}")

            # --- LOGIC FOR RSS SOURCES ---
            if source_type == 'rss':
                try:
                    # We wrap the parser in a try block in case the network fails
                    feed_data = feedparser.parse(feed_info['url'])
                    
                    # Check if feedparser itself hit a bozo error (malformed feed)
                    if feed_data.bozo:
                        log(f"Warning: {feed_info['name']} had a minor parsing issue, but we will try anyway.")

                    for entry in feed_data.entries:
                        if hasattr(entry, 'published_parsed'):
                            try:
                                entry_date = datetime.fromtimestamp(time.mktime(entry.published_parsed))
                                if entry_date > rss_threshold_date:
                                    all_collected_articles.append((
                                        raw_category_name,
                                        feed_info['name'],
                                        entry.get('title', 'No Title'),
                                        entry.get('link', 'No Link'),
                                        clean_html(entry.get('description', '')),
                                        entry_date.strftime('%Y-%m-%d %H:%M:%S')
                                    ))
                            except Exception:
                                continue # Skip entries with bad date formats
                except Exception as e:
                    log(f"Could not reach {feed_info['name']}. Network Error: {e}")

            # --- LOGIC FOR REDDIT JSON SOURCES ---
            elif source_type == 'json':
                try:
                    # We add 'verify=False' to the request as a safety net for SSL
                    headers = {'User-Agent': 'CyberIntelBot/0.1 by LearningUser'}
                    response = requests.get(feed_info['url'], headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        posts = data.get('data', {}).get('children', [])
                        
                        for post in posts:
                            post_data = post.get('data', {})
                            created_ts = post_data.get('created_utc')
                            if created_ts:
                                post_date = datetime.fromtimestamp(created_ts)
                                if post_date > json_threshold_date:
                                    all_collected_articles.append((
                                        "community_pulse",
                                        post_data.get('subreddit_name_prefixed', 'Unknown Subreddit'),
                                        post_data.get('title', 'No Title'),
                                        post_data.get('url', 'No Link'),
                                        clean_html(post_data.get('selftext', '')),
                                        post_date.strftime('%Y-%m-%d %H:%M:%S')
                                    ))
                    else:
                        log(f"Failed to fetch JSON: HTTP {response.status_code}")
                
                except Exception as e:
                    log(f"Error parsing JSON source {feed_info['name']}: {e}")

    # 4. FINAL SAVE TO SQLITE
    try:
        conn = init_db()
        c = conn.cursor()

        # OVERWRITE LOGIC: 
        # Before inserting new data, we clear the existing table 
        # to ensure Treya only carries the last 168 hours of intelligence.
        log("Clearing previous intelligence data to maintain 168-hour window...")
        c.execute("DELETE FROM raw_news")
        
        if not all_collected_articles:
            log("No new articles found in this run. Table remains empty.")
            conn.commit()
            conn.close()
            return

        # We use INSERT OR IGNORE to prevent crashing on duplicate URLs
        # ? placeholders are used for security (preventing SQL injection)
        c.executemany('''
            INSERT OR IGNORE INTO raw_news 
            (raw_category, source_name, title, link, description, published) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', all_collected_articles)
        
        conn.commit()
        
        # Check how many were inserted
        inserted_count = c.rowcount
        log(f"Success! Database updated. {inserted_count} articles added to the fresh crawl.")
        
        conn.close()
        
    except Exception as e:
        log(f"Error saving to database: {e}")

if __name__ == "__main__":
    fetch_all_intel()