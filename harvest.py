import subprocess
import sys
import os

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

CRAWL = os.path.join(SCRIPT_DIR, "intel", "crawl.py")
BREADCRUMB = os.path.join(SCRIPT_DIR, "intel", "breadcrumbs.py")
FEEDS = os.path.join(SCRIPT_DIR, "intel", "harvest", "external_feeds.py")
TRENDS = os.path.join(SCRIPT_DIR, "intel", "harvest", "calculate_trends.py")
SELECT_TOPICS = os.path.join(SCRIPT_DIR, "intel", "harvest", "select_topics.py")
DIVE = os.path.join(SCRIPT_DIR, "intel", "harvest", "deep_dive.py")
DIVE_REDDIT = os.path.join(SCRIPT_DIR, "intel", "harvest", "deep_dive_reddit_formatter.py")
GENERATE_REPORT = os.path.join(SCRIPT_DIR, "intel", "harvest", "report_generator.py")
EXTRACT_BREADCRUMBS = os.path.join(SCRIPT_DIR, "intel", "harvest", "breadcrumb_extract.py")

def run_scripts():
    # Define the list of scripts and their absolute or relative paths
    scripts_to_run = [
        {"name": "crawl.py", "path": CRAWL},
        {"name": "breadcrumbs.py", "path": BREADCRUMB},
        {"name": "external_feeds.py", "path": FEEDS},
        {"name": "calculate_trends.py", "path": TRENDS},
        {"name": "select_topics.py", "path": SELECT_TOPICS},
        {"name": "deep_dive.py", "path": DIVE},
        {"name": "deep_dive_reddit_formatter.py", "path": DIVE_REDDIT},
        {"name": "report_generator.py", "path": GENERATE_REPORT},
        {"name": "breadcrumb_extract.py", "path": EXTRACT_BREADCRUMBS}
    ]

    for script in scripts_to_run:
        script_name = script["name"]
        script_path = script["path"]

        print(f"Initiating {script_name}...")

        try:
            # sys.executable ensures we use the same Python interpreter currently running this script
            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                check=True # Raises CalledProcessError if the script exits with a non-zero status
            )
            print(f"Successfully ran {script_name}.")
            
        except subprocess.CalledProcessError as e:
            # Captures standard error output from the failed script
            error_msg = e.stderr.strip() if e.stderr else "Unknown error (no stderr output)"
            print(f"Error running {script_name}: {error_msg}")
            # Stop the pipeline if a script fails (optional, remove the break if you want it to continue)
            break
            
        except FileNotFoundError:
            print(f"Error running {script_name}: The file at {script_path} was not found.")
            break
            
        except Exception as e:
            print(f"Error running {script_name}: {str(e)}")
            break

if __name__ == "__main__":
    run_scripts()