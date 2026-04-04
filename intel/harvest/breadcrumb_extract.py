import json
import os
import sys
import sqlite3

# Dynamically link the 'app' directory so we can import the lookup script
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
app_dir = os.path.join(project_root, 'app')
sys.path.append(app_dir)

try:
    from breadcrumb_lookup import process_breadcrumb
except ImportError:
    print("Error: Could not import breadcrumb_lookup.py. Please check the directory structure.")
    sys.exit(1)

def extract_breadcrumbs_from_json(data):
    """
    Recursively search for all arrays named 'breadcrumbs' and extract their items.
    Using a set automatically handles duplicates within the JSON file itself.
    """
    found_breadcrumbs = set() 
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "breadcrumbs" and isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        found_breadcrumbs.add(item)
            else:
                found_breadcrumbs.update(extract_breadcrumbs_from_json(value))
    elif isinstance(data, list):
        for item in data:
            found_breadcrumbs.update(extract_breadcrumbs_from_json(item))
    return list(found_breadcrumbs)

def process_report_candidates(json_filename="report_candidates.json"):
    # Set up the paths relative to this script's location
    json_path = os.path.join(script_dir, json_filename)
    db_path = os.path.join(script_dir, '..', 'parsed_data', 'parsed_intel.sqlite')
    
    if not os.path.exists(json_path):
        print(f"Error: JSON file not found at {json_path}")
        return
        
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        return

    # 1. Load the JSON data
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print("Error: Failed to decode the JSON file. Please check its formatting.")
        return

    # 2. Extract all breadcrumbs nested anywhere in the file
    all_breadcrumbs = extract_breadcrumbs_from_json(data)
    print(f"Extracted {len(all_breadcrumbs)} unique breadcrumbs from the JSON file.")
    print("Starting database cross-reference...\n")

    # 3. Connect to the database for deduplication checking
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    processed_count = 0
    skipped_count = 0

    # 4. Iterate and check database conditions
    for breadcrumb in all_breadcrumbs:
        cursor.execute("SELECT context FROM breadcrumbs WHERE breadcrumb = ? LIMIT 1", (breadcrumb,))
        row = cursor.fetchone()

        if row:
            context = row[0]
            # Check if context exists and begins with "status:"
            if context and context.lower().startswith("status:"):
                print(f"[ACTION] Passing to lookup script: '{breadcrumb}'")
                # Pass the breadcrumb to our previously created script
                process_breadcrumb(breadcrumb)
                processed_count += 1
            else:
                # Skip if the context does not start with 'status:' 
                # (e.g. it already has an AI summary or is completely empty)
                skipped_count += 1
        else:
            # Skip if the breadcrumb isn't found in the database at all
            skipped_count += 1

    conn.close()

    # 5. Print completion message to the command line
    print("\n" + "="*30)
    print("--- BREADCRUMB PROCESSING COMPLETE ---")
    print(f"Total breadcrumbs passed to AI: {processed_count}")
    print(f"Total breadcrumbs skipped: {skipped_count}")
    print("="*30 + "\n")

if __name__ == "__main__":
    process_report_candidates()