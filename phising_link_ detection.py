import re
import requests
import whois
import urllib.parse
import csv

# OpenPhish API URL (public phishing feed)
OPENPHISH_FEED = "https://openphish.com/feed.txt"

# Function to check if URL is valid
def is_valid_url(url):
    pattern = re.compile(r"https?://[^\s/$.?#].[^\s]*")
    return re.match(pattern, url) is not None

# Function to check if URL is in OpenPhish blacklist
def check_blacklist(url):
    try:
        response = requests.get(OPENPHISH_FEED)
        phishing_urls = response.text.split("\n")
        return url in phishing_urls
    except requests.RequestException:
        return False

# Function to extract domain info using WHOIS
def get_domain_info(url):
    try:
        domain = urllib.parse.urlparse(url).netloc
        whois_info = whois.whois(domain)
        return {
            "domain": domain,
            "creation_date": whois_info.creation_date,
            "expiration_date": whois_info.expiration_date,
        }
    except Exception as e:
        return {"error": str(e)}

# Function to analyze URL and return results
def analyze_url(url):
    if not is_valid_url(url):
        return {"url": url, "error": "Invalid URL format"}

    result = {"url": url, "blacklisted": check_blacklist(url)}
    domain_info = get_domain_info(url)
    result.update(domain_info)

    return result

# Function to process multiple URLs from a file
def process_urls_from_file(input_file, output_file):
    with open(input_file, "r") as file:
        urls = [line.strip() for line in file.readlines()]

    results = [analyze_url(url) for url in urls]

    # Save results to CSV
    with open(output_file, "w", newline="") as csvfile:
        fieldnames = ["url", "blacklisted", "domain", "creation_date", "expiration_date", "error"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Report saved to {output_file}")

# Example usage
if __name__ == "__main__":
    input_file = "C:/Users/Airos/OneDrive/Desktop/Python programming/urls.txt"   # Create a file with URLs (one per line)
    output_file = "report.csv"
    process_urls_from_file(input_file, output_file)
