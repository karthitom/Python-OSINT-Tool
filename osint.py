The Automated OSINT Framework 🕵️‍♂️

This command-line tool takes any target domain and performs a complete intelligence-gathering sweep.

Key Features:

🌍 WHOIS & IP Geolocation: Automatically fetches domain registration data, expiry dates, and pinpoints the server's physical location and ISP.

🛡️ DNS Record Enumeration: Queries the target's DNS records to find MX (Mail Server) and TXT (Security/SPF) records.

🔎 Attack Surface Discovery: Uses a custom wordlist to brute-force and discover hidden subdomains (api.target.com) and directories (target.com/admin).

📧 Email & Socials Scraping: Crawls the website to find and extract any publicly available email addresses and social media links.

📈 Automated Reporting: Compiles all findings into a clean, timestamped .txt report for analysis.

Tech Stack: Python, requests, BeautifulSoup, python-whois, ipapi, dnspython.

Building this was a fantastic deep dive into how OSINT really works. (Big thanks to Gemini for the guidance!)

Next up, I'll be sharing my Network Scanner project.

#Cybersecurity #Python #OSINT #PenetrationTesting #EthicalHacking #Projects #Automation #KaliLinux #Reconnaissance
