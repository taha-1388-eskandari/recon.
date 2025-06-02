import socket
import re
import sqlite3
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import dns.resolver
import whois
from flask import Flask, request, render_template

app = Flask(__name__)
DB_FILE = 'results.db'
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080, 8443]

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    urls TEXT,
                    subdomains TEXT,
                    ports TEXT,
                    emails TEXT,
                    phones TEXT,
                    whois TEXT
                )''')
    conn.commit()
    conn.close()

def save_to_db(target, urls, subdomains, ports, emails, phones, whois_data):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM history WHERE target = ?", (target,))
    c.execute("INSERT INTO history (target, urls, subdomains, ports, emails, phones, whois) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (target, urls, subdomains, ports, emails, phones, whois_data))
    conn.commit()
    conn.close()

def fetch(url):
    try:
        response = requests.get(url, timeout=5)
        return response.text
    except:
        return ''

def get_status_code(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code
    except:
        return None

def crawl(domain, depth=2):
    visited = set()
    to_visit = [(f"http://{domain}", 0)]
    found_urls = []

    while to_visit:
        current_url, current_depth = to_visit.pop()
        if current_url in visited or current_depth > depth:
            continue
        visited.add(current_url)
        html = fetch(current_url)
        found_urls.append(current_url)
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = urljoin(current_url, a['href'])
            parsed = urlparse(href)
            if parsed.scheme.startswith('http') and parsed.netloc == domain:
                to_visit.append((href, current_depth + 1))
    return list(set(found_urls))

def get_title(url):
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, 'html.parser')
        return soup.title.string.strip() if soup.title else 'No Title'
    except:
        return 'Error'

def extract_info(url):
    html = fetch(url)
    emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@gmail\.com", html))
    phones = set(re.findall(r"\b09\d{9}\b", html))
    return emails, phones

def resolve_subdomains(domain, wordlist):
    resolver = dns.resolver.Resolver()
    found = []
    for word in wordlist:
        sub = f"{word}.{domain}"
        try:
            resolver.resolve(sub, 'A')
            found.append(sub)
        except:
            pass
    return found

def scan_ports(ip):
    open_ports = []
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=0.2):
                open_ports.append(port)
        except:
            continue
    return open_ports

def get_whois_info(domain):
    try:
        return str(whois.whois(domain))
    except:
        return 'WHOIS lookup failed'

def do_recon(domain):
    wordlist = [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'imap', 'pop', 'ns1', 'ns2', 'mx',
        'api', 'dev', 'test', 'staging', 'beta', 'admin', 'portal', 'web', 'cdn', 'cloud',
        'shop', 'store', 'vpn', 'secure', 'login', 'auth', 'dashboard', 'static', 'files',
        'media', 'images', 'gateway', 'crm', 'git', 'gitlab', 'jira', 'status', 'monitor',
        'help', 'support', 'docs', 'forum', 'forums', 'news', 'blog', 'video', 'videos',
        'analytics', 'accounts', 'account', 'sso', 'intranet', 'extranet', 'newsletter',
        'proxy', 'proxy1', 'proxy2', 'server', 'server1', 'server2', 'server3', 'mailserver',
        'mail1', 'mail2', 'securemail', 'mta', 'autodiscover', 'owa', 'exchange', 'owncloud',
        'nextcloud', 'vpn1', 'vpn2', 'login1', 'login2', 'static1', 'static2', 'db', 'database',
        'backup', 'adminpanel', 'cpanel', 'webapp', 'app', 'mobile', 'm', 'test1', 'test2',
        'sandbox', 'demo', 'shop1', 'shop2', 'fileserver', 'cloud1', 'cloud2', 'mailhost'
    ]

    urls = crawl(domain)
    url_info = []
    emails_all, phones_all = set(), set()

    for url in urls:
        netloc = urlparse(url).netloc
        if not netloc:
            continue
        try:
            ip = socket.gethostbyname(netloc)
        except socket.gaierror:
            continue
        ports = scan_ports(ip)
        title = get_title(url)
        status_code = get_status_code(url)
        emails, phones = extract_info(url)
        url_info.append((url, ip, ports, title, status_code))
        emails_all.update(emails)
        phones_all.update(phones)

    subdomains = resolve_subdomains(domain, wordlist)
    sub_info = []

    for sub in subdomains:
        sub_url = f"http://{sub}"
        try:
            ip = socket.gethostbyname(sub)
        except socket.gaierror:
            continue
        ports = scan_ports(ip)
        title = get_title(sub_url)
        status_code = get_status_code(sub_url)
        emails, phones = extract_info(sub_url)
        sub_info.append((sub, ip, ports, title, status_code))
        emails_all.update(emails)
        phones_all.update(phones)

    whois_info = get_whois_info(domain)

    save_to_db(domain, str(urls), str(subdomains), str(sub_info),
               str(emails_all), str(phones_all), whois_info)

    return domain, url_info, sub_info, emails_all, phones_all, whois_info


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        domain, url_info, sub_info, emails_all, phones_all, whois_info = do_recon(domain)
        return render_template('report.html',
                               domain=domain,
                               urls=url_info,
                               sub_info=sub_info,
                               emails=emails_all,
                               phones=phones_all,
                               whois=whois_info)
    return render_template('index.html')


@app.route('/user/<domain>', methods=['GET'])
def user(domain):
    domain, url_info, sub_info, emails_all, phones_all, whois_info = do_recon(domain)
    return render_template('report.html',
                           domain=domain,
                           urls=url_info,
                           sub_info=sub_info,
                           emails=emails_all,
                           phones=phones_all,
                           whois=whois_info)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
