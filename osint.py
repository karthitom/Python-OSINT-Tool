import requests
from bs4 import BeautifulSoup
import re
import sys
from urllib.parse import urljoin, urlparse
import socket
import time
from datetime import datetime
import whois
import ipapi
import dns.resolver 

# --- Constants ---
SOCIAL_SITES = [
    'twitter.com', 'linkedin.com', 'github.com', 
    'facebook.com', 'instagram.com', 'youtube.com'
]
EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# --- Global storage sets ---
all_found_emails = set()
all_found_socials = set()
all_found_tech = set()
all_found_headers = set()
all_found_subdomains = set()
all_found_whois = []
all_found_ip_info = []
all_found_dns_records = [] 
scanned_urls = set()

# --- DNS Record Function ---
def get_dns_records(base_domain):
    """
    Fetches common DNS records (MX and TXT).
    """
    print(f"\n--- Fetching DNS Records for {base_domain} ---")
    
    # MX Records (Mail Servers)
    try:
        mx_records = dns.resolver.resolve(base_domain, 'MX')
        all_found_dns_records.append("--- MX Records (Mail Servers) ---")
        for rdata in mx_records:
            record = f"  Priority: {rdata.preference}, Server: {rdata.exchange.to_text()}"
            print(f"[+] {record}")
            all_found_dns_records.append(record)
    except Exception as e:
        print(f"[-] Could not find MX records: {e}")

    # TXT Records (Security/Verification)
    try:
        txt_records = dns.resolver.resolve(base_domain, 'TXT')
        all_found_dns_records.append("\n--- TXT Records (Verification/SPF) ---")
        for rdata in txt_records:
            record = f"  {rdata.to_text()}"
            print(f"[+] {record}")
            all_found_dns_records.append(record)
    except Exception as e:
        print(f"[-] Could not find TXT records: {e}")


def get_ip_info(base_domain):
    """ Finds the IP address and gets geolocation info. """
    print(f"\n--- Performing IP Info Lookup for {base_domain} ---")
    try:
        ip_address = socket.gethostbyname(base_domain)
        print(f"[+] IP Address: {ip_address}")
        all_found_ip_info.append(f"IP Address: {ip_address}")
        info = ipapi.location(ip=ip_address)
        if not info:
            print("[-] IP info not found.")
            return
        if 'city' in info:
            print(f"[+] City: {info['city']}")
            all_found_ip_info.append(f"City: {info['city']}")
        if 'country_name' in info:
            print(f"[+] Country: {info['country_name']}")
            all_found_ip_info.append(f"Country: {info['country_name']}")
        if 'org' in info:
            print(f"[+] ISP / Org: {info['org']}")
            all_found_ip_info.append(f"ISP / Org: {info['org']}")
    except socket.error as e:
        print(f"[-] Could not find IP Address: {e}")
    except Exception as e:
        print(f"[-] IP info lookup failed: {e}")


def get_whois_info(base_domain):
    """ Performs a WHOIS lookup on the base domain. """
    print(f"\n--- Performing WHOIS Lookup for {base_domain} ---")
    try:
        w = whois.whois(base_domain)
        if w.registrar:
            print(f"[+] Registrar: {w.registrar}")
            all_found_whois.append(f"Registrar: {w.registrar}")
        if w.creation_date:
            print(f"[+] Creation Date: {w.creation_date}")
            all_found_whois.append(f"Creation Date: {w.creation_date}")
        if w.expiration_date:
            print(f"[+] Expiration Date: {w.expiration_date}")
            all_found_whois.append(f"Expiration Date: {w.expiration_date}")
        if w.name_servers:
            print(f"[+] Name Servers: {w.name_servers}")
            all_found_whois.append(f"Name Servers: {', '.join(w.name_servers)}")
    except Exception as e:
        print(f"[-] WHOIS lookup failed: {e}")


def find_subdomains(base_domain, wordlist_file):
    """ Tries to find common subdomains from a wordlist file. """
    print(f"\n--- Checking for Subdomains using '{wordlist_file}' ---")
    try:
        with open(wordlist_file, 'r') as f:
            for line in f:
                sub = line.strip() 
                if not sub: continue 
                target = f"{sub}.{base_domain}"
                try:
                    socket.gethostbyname(target)
                    print(f"[+] Found Subdomain: {target}")
                    all_found_subdomains.add(target)
                except socket.error:
                    pass 
                time.sleep(0.01) 
    except FileNotFoundError:
        print(f"[ERROR] Wordlist file not found: '{wordlist_file}'")
    if not all_found_subdomains:
        print("[-] Nothing found from the wordlist.")


def find_directories(base_url, wordlist_file):
    """ Tries to find common directories on the server. """
    print(f"\n--- Checking for Common Directories using '{wordlist_file}' ---")
    all_found_dirs = set()
    try:
        with open(wordlist_file, 'r') as f:
            for line in f:
                dir_name = line.strip()
                if not dir_name: continue
                if dir_name.startswith('/'):
                    dir_name = dir_name[1:]
                target_url = urljoin(base_url, dir_name)
                try:
                    response = requests.head(target_url, timeout=3, allow_redirects=True)
                    if response.status_code != 404:
                        print(f"[+] Found Directory/File: {target_url} (Status: {response.status_code})")
                        all_found_dirs.add(target_url)
                except requests.exceptions.RequestException:
                    pass 
                time.sleep(0.01)
    except FileNotFoundError:
        print(f"[ERROR] Wordlist file not found: '{wordlist_file}'")
    if not all_found_dirs:
        print("[-] Could not find any common directories from the wordlist.")


def scan_page_for_info(url, response, soup):
    """ Extracts info and adds to global sets """
    for link in soup.find_all('a', href=re.compile(r'^mailto:')):
        all_found_emails.add(link['href'].replace('mailto:', ''))
    emails_in_text = re.findall(EMAIL_REGEX, soup.get_text())
    all_found_emails.update(emails_in_text)
    for link in soup.find_all('a', href=True):
        href = link['href']
        for site in SOCIAL_SITES:
            if site in href:
                all_found_socials.add(href)
                break
    if not all_found_headers: 
        if 'Server' in response.headers:
            all_found_headers.add(f"Server: {response.headers['Server']}")
        if 'X-Powered-By' in response.headers:
            all_found_headers.add(f"X-Powered-By: {response.headers['X-Powered-By']}")
        if 'Set-Cookie' in response.headers:
             all_found_headers.add(f"Cookies: (Site uses cookies)")
    generator_tag = soup.find('meta', attrs={'name': 'generator'})
    if generator_tag and generator_tag.get('content'):
        all_found_tech.add(f"Generator: {generator_tag.get('content')}")
    if "wp-content" in response.text:
        all_found_tech.add("Technology: WordPress (Found 'wp-content')")


def check_common_files(base_url):
    """ Checks for 'robots.txt' and 'sitemap.xml' """
    print("\n--- Checking Common Files ---")
    try:
        robots_url = urljoin(base_url, '/robots.txt')
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200 and 'User-agent:' in response.text:
            print(f"[+] Found 'robots.txt' at: {robots_url}")
            print("    " + "\n    ".join(response.text.splitlines()[:5]))
        else:
            print("[-] 'robots.txt' not found.")
    except requests.exceptions.RequestException:
        print("[-] Error while checking 'robots.txt'.")
    try:
        sitemap_url = urljoin(base_url, '/sitemap.xml')
        response = requests.get(sitemap_url, timeout=5)
        if response.status_code == 200 and '<urlset' in response.text:
            print(f"[+] Found 'sitemap.xml' at: {sitemap_url}")
        else:
            print("[-] 'sitemap.xml' not found.")
    except requests.exceptions.RequestException:
        pass


def crawl_site(start_url):
    """ Main crawl function """
    urls_to_scan = set([start_url]) 
    base_domain = urlparse(start_url).netloc
    check_common_files(start_url)
    print("\n--- Starting Page Crawl (Max 10 pages) ---")
    while urls_to_scan and len(scanned_urls) < 10: 
        current_url = urls_to_scan.pop() 
        if current_url in scanned_urls: continue 
        try:
            response = requests.get(current_url, timeout=5)
            if response.status_code != 200: continue 
        except requests.exceptions.RequestException as e:
            print(f"[!] URL skipped (Error): {current_url} - {e}")
            continue 
        
        print(f"---> Scanning: {current_url}")
        scanned_urls.add(current_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        scan_page_for_info(current_url, response, soup)
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(start_url, href)
            link_domain = urlparse(full_url).netloc
            if link_domain == base_domain and \
               full_url not in scanned_urls and \
               full_url not in urls_to_scan:
                if not any(ext in full_url.lower() for ext in ['.jpg', '.png', '.css', '.js', '.pdf', '.zip']):
                    urls_to_scan.add(full_url)
    generate_report(base_domain)


def generate_report(base_domain):
    """
    Prints the report to console and saves it to a file.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{base_domain.replace('.', '_')}_{timestamp}.txt"
    
    report_content = []
    report_content.append("="*30)
    report_content.append(f"OSINT REPORT FOR: {base_domain}")
    report_content.append(f"Scanned {len(scanned_urls)} pages.")
    report_content.append("="*30)

    report_content.append("\n--- IP & HOSTING INFORMATION ---")
    if all_found_ip_info:
        for info in all_found_ip_info:
            report_content.append(info)
    else:
        report_content.append("No IP info found.")

    report_content.append("\n--- WHOIS INFORMATION ---")
    if all_found_whois:
        for info in all_found_whois:
            report_content.append(info)
    else:
        report_content.append("No WHOIS info found.")
        
    report_content.append("\n--- DNS RECORDS (MX, TXT) ---")
    if all_found_dns_records:
        for info in all_found_dns_records:
            report_content.append(info)
    else:
        report_content.append("No DNS records found.")

    report_content.append("\n--- ALL FOUND SUBDOMAINS ---")
    if all_found_subdomains:
        for sub in all_found_subdomains:
            report_content.append(sub)
    else:
        report_content.append("No subdomains found.")

    report_content.append("\n--- FOUND TECHNOLOGIES & HEADERS ---")
    if all_found_headers or all_found_tech:
        for item in all_found_headers.union(all_found_tech):
            report_content.append(f"[+] {item}")
    else:
        report_content.append("No technology info found.")

    report_content.append("\n--- ALL FOUND EMAILS ---")
    if all_found_emails:
        for email in all_found_emails:
            report_content.append(email)
    else:
        report_content.append("No emails found.")

    report_content.append("\n--- ALL FOUND SOCIAL LINKS ---")
    if all_found_socials:
        for link in all_found_socials:
            report_content.append(link)
    else:
        report_content.append("No social media links found.")

    print("\n\n" + "\n".join(report_content))

    try:
        with open(filename, 'w') as f:
            f.write("\n".join(report_content))
        print(f"\n[SUCCESS] Report successfully saved to: {filename}")
    except IOError as e:
        print(f"\n[ERROR] Could not save report: {e}")


# --- Script start ---
if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("Enter the website URL to scan (e.g., https://example.com): ")
    
    wordlist = "wordlist.txt" 

    if not target_url.startswith('http://') and not target_url.startswith('https://'):
        target_url = 'https://' + target_url

    parsed_url = urlparse(target_url)
    domain_parts = parsed_url.netloc.split('.')
    if len(domain_parts) > 2:
        base_domain = ".".join(domain_parts[-2:])
        if domain_parts[-2] in ['co', 'com', 'org', 'net']:
             base_domain = ".".join(domain_parts[-3:])
    else:
        base_domain = parsed_url.netloc

    print(f"Base Domain identified as: {base_domain}")

    # 1. Checking IP info
    get_ip_info(base_domain)

    # 2. Checking WHOIS
    get_whois_info(base_domain)
    
    # 3. Checking DNS
    get_dns_records(base_domain)
    
    # 4. Finding subdomains
    find_subdomains(base_domain, wordlist)
    
    # 5. Finding directories
    find_directories(target_url, wordlist)
    
    # 6. Crawling the URL given by user
    # --- BUG FIX INGA ---
    crawl_site(target_url) 
