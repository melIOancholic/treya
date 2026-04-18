import sqlite3
import os
from datetime import datetime, timedelta

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "..", "parsed_data", "parsed_intel.sqlite")

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

def init_trends_table(conn):
    """
    Ensures the breadcrumbs_trends_full table exists with base columns.
    (Step 1: Check if table exists, if not, create it).
    """
    query = """
    CREATE TABLE IF NOT EXISTS breadcrumbs_trends_full (
        id INTEGER PRIMARY KEY,
        breadcrumb TEXT,
        results TEXT,
        "rolling_average" REAL
    )
    """
    conn.execute(query)
    conn.commit()

def get_date_columns(conn):
    """Helper function to extract all YYYY-MM-DD column names from the table."""
    cursor = conn.execute("PRAGMA table_info(breadcrumbs_trends_full)")
    columns = [row['name'] for row in cursor.fetchall()]
    date_cols = []
    
    for col in columns:
        try:
            # Check if column name strictly matches a date format
            datetime.strptime(col, '%Y-%m-%d')
            date_cols.append(col)
        except ValueError:
            pass
            
    return date_cols

def maintain_rolling_window_columns(conn, target_date):
    """
    Drops date columns older than the 31-day window relative to the target_date.
    (Step 2: Drop older columns. Used a 31-day cutoff to preserve the "rolling_average" side-by-side view).
    """
    date_cols = get_date_columns(conn)
    dt = datetime.strptime(target_date, '%Y-%m-%d')
    cutoff_date = (dt - timedelta(days=31)).strftime('%Y-%m-%d')

    for col in date_cols:
        if col < cutoff_date:
            try:
                # SQLite 3.35.0+ supports dropping columns
                conn.execute(f'ALTER TABLE breadcrumbs_trends_full DROP COLUMN "{col}"')
                print(f"[*] Dropped expired date column: {col}")
            except sqlite3.OperationalError as e:
                print(f"[!] Error dropping column '{col}'. Ensure SQLite is >= 3.35.0: {e}")
    conn.commit()

def process_todays_data(conn, target_date):
    """
    Checks for today's column and applies counts from the breadcrumbs table.
    (Step 3).
    """
    date_cols = get_date_columns(conn)
    
    if target_date in date_cols:
        print("Today's breadcrumbs have already been metricized.")
        return
        
    print(f"[*] Adding new column and pulling metrics for {target_date}...")
    
    # Add today's column
    conn.execute(f'ALTER TABLE breadcrumbs_trends_full ADD COLUMN "{target_date}" INTEGER DEFAULT 0')
    
    # Ensure every breadcrumb from the 'breadcrumbs' table is present
    conn.execute('''
        INSERT INTO breadcrumbs_trends_full (id, breadcrumb)
        SELECT id, breadcrumb FROM breadcrumbs
        WHERE id NOT IN (SELECT id FROM breadcrumbs_trends_full)
    ''')
    
    # OPTIMIZATION: Instead of a correlated SQL subquery which lags on 5000+ rows, 
    # we pull the data into memory and use executemany for a fast, single-transaction batch update.
    cursor = conn.execute("SELECT id, count FROM breadcrumbs")
    counts_data = cursor.fetchall()
    
    update_batch = [(row['count'], row['id']) for row in counts_data]
    
    conn.executemany(f'''
        UPDATE breadcrumbs_trends_full
        SET "{target_date}" = ?
        WHERE id = ?
    ''', update_batch)
    
    conn.commit()

def calculate_and_update_surges(conn, target_date):
    """
    Calculates surges, identifies the top 50, updates their results, 
    and calculates global rolling_average columns for ALL history.
    (Step 4 & 5).
    """
    date_cols = get_date_columns(conn)
    date_cols.sort()
    
    if not date_cols:
        print("[!] No date columns found to calculate surges.")
        return

    cursor = conn.execute("SELECT * FROM breadcrumbs_trends_full")
    rows = cursor.fetchall()
    
    analyzed_data = []
    
    for row in rows:
        row_dict = dict(row)
        row_id = row_dict['id']
        
        # Extract all date counts for this specific breadcrumb
        counts = {}
        for col in date_cols:
            val = row_dict[col]
            counts[col] = val if val is not None else 0
            
        today_val = counts.get(target_date, 0)
        
        # Determine the baseline using dates strictly older than target_date
        past_dates = [col for col in date_cols if col < target_date]
        past_counts = [counts[d] for d in past_dates]
        
        if past_counts:
            baseline = sum(past_counts) / len(past_counts)
        else:
            baseline = 0.0
            
        # Calculate overall rolling_average (includes today's data)
        all_counts = [counts[d] for d in date_cols]
        rolling_avg = sum(all_counts) / len(all_counts) if all_counts else 0.0
        
        # Calculate surge using the +1 buffer logic
        surge_pct = ((today_val - baseline) / (baseline + 1)) * 100
        
        # Format the text output for the 'results' column
        result_text = f"Surge: {surge_pct:+.2f}% (Today: {today_val} | Baseline: {baseline:.2f})"
        
        analyzed_data.append({
            'id': row_id,
            'surge_pct': surge_pct,
            'result_text': result_text,
            'rolling_avg': round(rolling_avg, 2)
        })
        
    # Sort by highest surge descending
    analyzed_data.sort(key=lambda x: x['surge_pct'], reverse=True)
    
    if not analyzed_data:
        print("[!] No data available to update.")
        return

    # Split into Top 50 (who get text results) and the rest (who just get their averages updated)
    top_50 = analyzed_data[:50]
    the_rest = analyzed_data[50:]
    
    # Format the batch updates
    # Structure: (results_text, rolling_average, id)
    top_50_updates = [(item['result_text'], item['rolling_avg'], item['id']) for item in top_50]
    the_rest_updates = [(None, item['rolling_avg'], item['id']) for item in the_rest]
    
    # Combine lists so we can perform one massive transaction update
    all_updates = top_50_updates + the_rest_updates

    # Perform the batch update using executemany (highly optimized for thousands of rows)
    conn.executemany('''
        UPDATE breadcrumbs_trends_full
        SET results = ?, "rolling_average" = ?
        WHERE id = ?
    ''', all_updates)
    
    conn.commit()
    print(f"[*] Batch updated Top 50 surges and {len(all_updates)} total rolling averages. History safely preserved.")

def main():
    print("[*] Starting Trend Analysis Engine...")
    conn = get_db_connection()
    if not conn: return

    # Get the date from the data, not the system clock
    target_date = get_latest_data_date(conn)
    print(f"[*] Target Date for analysis: {target_date}")

    # 1. Initialize table if it doesn't exist
    init_trends_table(conn)
    
    # 2. Drop old tracking columns to maintain a clean rolling window 
    maintain_rolling_window_columns(conn, target_date)
    
    # 3. Handle today's metrics
    process_todays_data(conn, target_date)
    
    # 4 & 5. Calculate surges and write text strings/averages directly to DB
    print("[*] Calculating Frequency Surges...")
    calculate_and_update_surges(conn, target_date)
    
    print("[*] Analysis complete. Database updated with side-by-side trends.")
    
    conn.close()

if __name__ == "__main__":
    main()