import json
import re
import requests
import time
import random
import os
from pathlib import Path

# Define the path to the report_candidates.json file
# Using pathlib ensures this works smoothly on both Windows and Linux environments
CACHE_DIR = Path("intel") / "harvest" / "cache"
FILE_PATH = CACHE_DIR / "report_candidates.json"

# Regex to match a Reddit URL and extract the subreddit and the ID.
# Matches: https://www.reddit.com/r/<subreddit>/comments/<id>/<optional_title>
REDDIT_REGEX = re.compile(r"https?://(?:www\.)?reddit\.com/r/([a-zA-Z0-9_]+)/comments/([a-zA-Z0-9]+)")

def fetch_reddit_comments(subreddit, post_id):
    """
    Fetches the JSON representation of a Reddit thread and extracts the top 3 comments.
    """
    # Constructing the URL dynamically based on the matched subreddit and ID
    url = f"https://www.reddit.com/r/{subreddit}/comments/{post_id}.json"
    
    # Custom, descriptive user agent (Reddit will aggressively rate-limit or block standard Python requests user-agents)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 CyberCurationBot/1.0"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # If rate limited (429) or not found (404), fail gracefully
        if response.status_code != 200:
            print(f"[!] Failed to fetch {url}: HTTP Status {response.status_code}")
            return None

        data = response.json()
        
        # Reddit JSON returns a list: index 0 is the post, index 1 is the comment tree
        if not isinstance(data, list) or len(data) < 2:
            return None

        comments_list = data[1].get("data", {}).get("children", [])
        extracted_comments = []

        for child in comments_list:
            # 't1' is the Reddit API kind tag for a Comment object
            if child.get("kind") == "t1": 
                comment_data = child.get("data", {})
                body = comment_data.get("body", "").strip()
                
                # Only proceed if the body is not empty
                if body:
                    author = comment_data.get("author", "[deleted]")
                    ups = comment_data.get("ups", 0)
                    downs = comment_data.get("downs", 0)

                    # Clean the body text so it stays on one line and doesn't break JSON quotes
                    clean_body = body.replace("\n", " ").replace("\r", " ").replace('"', "'")
                    # Remove any extra whitespace created by removing newlines
                    clean_body = re.sub(r'\s+', ' ', clean_body)

                    # Format: User A (X, Y): "Z"
                    formatted_comment = f'{author} ({ups} upvotes, {downs} downvotes): "{clean_body}"'
                    extracted_comments.append(formatted_comment)

                    # Stop once we have 3 valid comments
                    if len(extracted_comments) == 10:
                        break

        # Join the list into a single comma-separated string ending with a period
        if extracted_comments:
            return ", ".join(extracted_comments) + "."
        
        return None

    except Exception as e:
        print(f"[!] Error fetching/parsing {url}: {e}")
        return None

def process_candidates():
    """
    Loads the candidates file, iterates through the arrays looking for community_pulse 
    articles, fetches Reddit comments for matched links, and saves the file.
    """
    if not FILE_PATH.exists():
        print(f"[!] Could not find file at: {FILE_PATH}")
        return

    print(f"[*] Loading {FILE_PATH}...")
    with open(FILE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    changes_made = False

    # Iterate over all categories
    for category_name, article_list in data.items():
        if not isinstance(article_list, list):
            continue

        for article in article_list:
            # Check condition: only proceed if raw_category is "community_pulse"
            if article.get("raw_category") == "community_pulse":
                
                # 1. Check the main 'link'
                main_link = article.get("link", "")
                match = REDDIT_REGEX.search(main_link)
                if match:
                    subreddit, post_id = match.groups()
                    print(f"[*] Fetching deep dive for main link: {main_link}")
                    
                    comments_string = fetch_reddit_comments(subreddit, post_id)
                    if comments_string:
                        article["deep_dive_context"] = comments_string
                        changes_made = True
                        print(f"  [+] Added {len(comments_string)} characters to deep_dive_context.")
                    
                    # Random sleep to prevent rate limiting (4 to 7 seconds)
                    sleep_time = random.uniform(4.0, 7.0)
                    time.sleep(sleep_time)

                # 2. Check 'link' fields within 'supplementary_articles'
                supp_articles = article.get("supplementary_articles", [])
                if isinstance(supp_articles, list):
                    for i, supp in enumerate(supp_articles):
                        if isinstance(supp, dict):
                            supp_link = supp.get("link", "")
                            match = REDDIT_REGEX.search(supp_link)
                            if match:
                                subreddit, post_id = match.groups()
                                print(f"[*] Fetching deep dive for supplementary link: {supp_link}")
                                
                                comments_string = fetch_reddit_comments(subreddit, post_id)
                                if comments_string:
                                    supp["deep_dive_context"] = comments_string
                                    changes_made = True
                                    print(f"  [+] Added {len(comments_string)} characters to supplementary_articles.")
                                
                                # Random sleep to prevent rate limiting (4 to 7 seconds)
                                sleep_time = random.uniform(4.0, 7.0)
                                time.sleep(sleep_time)

    # Save changes if any
    if changes_made:
        print(f"[*] Changes detected. Saving updated JSON to {FILE_PATH}...")
        with open(FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print("[+] Process complete.")
    else:
        print("[-] No changes were made (no eligible links or new comments found).")

if __name__ == "__main__":
    process_candidates()