# Python-OSINT-Tool
A Python-based OSINT tool to fetch WHOIS, DNS, subdomains, and scrape emails from a target domain.

# Automated OSINT Framework 

An automated, command-line OSINT (Open Source Intelligence) tool built in Python. It takes a target domain and performs a comprehensive reconnaissance sweep, gathering public information and saving it to a report.

This tool is designed for educational purposes and ethical penetration testing to automate the initial information-gathering phase.

## Key Features

* WHOIS & IP Geolocation: Automatically fetches domain registration data (registrar, creation/expiry dates) and pinpoints the server's physical location and ISP.
* DNS Record Enumeration: Queries the target's DNS records to find MX (Mail Server) and TXT (Security/SPF) records.
* Attack Surface Discovery: Uses a custom wordlist (`wordlist.txt`) to brute-force and discover hidden subdomains (`api.target.com`) and **directories (`target.com/admin`).
* Email & Socials Scraping:** Crawls the target website (up to 10 pages deep) to find and extract any publicly listed email addresses and **social media links.
* Automated Reporting: Compiles all findings into a clean, timestamped `.txt` report for analysis (e.g., `report_example_com_20251027.txt`).

## Tech Stack

* Python 3
* requests: For making HTTP requests and crawling.
* BeautifulSoup: For parsing HTML and scraping data.
* python-whois: For performing WHOIS lookups.
* ipapi: For IP geolocation.
* dnspython: For querying DNS records.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/karthitom/Python-OSINT-Tool.git
    cd Python-OSINT-Tool.git
    ```

2.  (Recommended) Create and activate a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  Install the required libraries:
    ```bash
    pip install -r requirements.txt
    ```

## How to Use

1.  Ensure you have a `wordlist.txt` file in the same directory.
2.  Run the script from your terminal:
    ```bash
    python3 osint.py
    ```
3.  The script will then prompt you to enter the target URL (e.g., `example.com`).

Once the scan is complete, a detailed report will be saved in the same directory.

## Disclaimer

This tool is intended for educational purposes and ethical testing only. Do not use this tool on any domain or system for which you do not have explicit written permission. The author is not responsible for any misuse or damage caused by this tool.
