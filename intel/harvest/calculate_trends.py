import sqlite3
import json
import csv
import os
from datetime import datetime, timedelta

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "..", "parsed_data", "parsed_intel.sqlite")
EXPORT_JSON = os.path.join(SCRIPT_DIR, "cache", "top_trends.json")
EXPORT_CSV = os.path.join(SCRIPT_DIR, "cache", "trends_full_report.csv")

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    db_dir = os.path.dirname(DB_PATH)
    if not os.path.exists(db_dir):
        print(f"[!] Path Error: The directory {db_dir} does not exist.")
        return None
        
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"[!] Database Connection Error: {e}")
        return None

def get_latest_data_date(conn):
    """Finds the most recent date present in the raw_news table."""
    query = "SELECT MAX(DATE(crawled_at)) as last_date FROM raw_news"
    row = conn.execute(query).fetchone()
    return row['last_date'] if row['last_date'] else datetime.now().strftime('%Y-%m-%d')

def init_metrics_table(conn):
    """
    Ensures the daily_metrics table exists.
    """
    query = """
    CREATE TABLE IF NOT EXISTS daily_metrics (
        date TEXT,
        breadcrumb_id INTEGER,
        unique_source_count INTEGER,
        PRIMARY KEY (date, breadcrumb_id)
    )
    """
    conn.execute(query)
    conn.commit()

def maintain_30_day_window(conn, target_date):
    """Deletes metric data older than 31 days relative to the target_date."""
    dt = datetime.strptime(target_date, '%Y-%m-%d')
    cutoff_date = (dt - timedelta(days=31)).strftime('%Y-%m-%d')
    conn.execute("DELETE FROM daily_metrics WHERE date <= ?", (cutoff_date,))
    conn.commit()

def update_daily_counts(conn, target_date):
    """
    Updates metrics based on a specific target date.
    Captures the breadcrumb ID and source count.
    Uses mapping_table to link breadcrumbs to news.
    """
    query = """
    INSERT OR REPLACE INTO daily_metrics (date, breadcrumb_id, unique_source_count)
    SELECT ?, sub.breadcrumb_id, COUNT(sub.source_name)
    FROM (
        SELECT DISTINCT b.id as breadcrumb_id, r.source_name
        FROM breadcrumbs b
        JOIN mapping_table m ON b.id = m.breadcrumb_id
        JOIN raw_news r ON m.news_id = r.id
        WHERE DATE(r.crawled_at) = ?
    ) as sub
    GROUP BY sub.breadcrumb_id
    """
    conn.execute(query, (target_date, target_date))
    conn.commit()

def calculate_surges(conn, target_date):
    """Calculates surges relative to the target_date."""
    query = """
    SELECT 
        b.breadcrumb,
        b.category,
        today.unique_source_count as today_count,
        COALESCE(avg_table.baseline, 0.0) as baseline
    FROM breadcrumbs b
    JOIN daily_metrics today ON b.id = today.breadcrumb_id AND today.date = ?
    LEFT JOIN (
        SELECT breadcrumb_id, AVG(unique_source_count) as baseline
        FROM daily_metrics
        WHERE date < ?
        GROUP BY breadcrumb_id
    ) as avg_table ON b.id = avg_table.breadcrumb_id
    """
    
    cursor = conn.execute(query, (target_date, target_date))
    results = []
    
    for row in cursor:
        today_val = row['today_count']
        baseline = row['baseline']
        surge_pct = ((today_val - baseline) / (baseline + 1)) * 100
        
        results.append({
            "breadcrumb": row['breadcrumb'],
            "category": row['category'],
            "today_count": today_val,
            "baseline": round(baseline, 2),
            "surge_pct": round(surge_pct, 2)
        })
    
    return sorted(results, key=lambda x: x['surge_pct'], reverse=True)

def export_results(results):
    """Exports results to JSON and CSV."""
    top_20 = results[:20]
    with open(EXPORT_JSON, 'w') as f:
        json.dump(top_20, f, indent=4)
    
    if results:
        keys = results[0].keys()
        with open(EXPORT_CSV, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(results)

def main():
    print("[*] Starting Trend Analysis Engine...")
    conn = get_db_connection()
    if not conn: return

    # Get the date from the data, not the system clock
    target_date = get_latest_data_date(conn)
    print(f"[*] Target Date for analysis: {target_date}")

    init_metrics_table(conn)
    
    # Maintain the 30-day window relative to the latest data
    maintain_30_day_window(conn, target_date)
    
    print(f"[*] Updating metrics for {target_date}...")
    update_daily_counts(conn, target_date)
    
    print("[*] Calculating Frequency Surges...")
    surge_results = calculate_surges(conn, target_date)
    
    print(f"[*] Analysis complete. Processed {len(surge_results)} active breadcrumbs.")
    export_results(surge_results)
    
    print(f"[+] Top 20 saved to {EXPORT_JSON}")
    print(f"[+] Full report saved to {EXPORT_CSV}")
    
    conn.close()

if __name__ == "__main__":
    main()