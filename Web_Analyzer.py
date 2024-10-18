import socket
import whois
import requests
from bs4 import BeautifulSoup
import nmap
import ssl
from datetime import datetime
from shodan import Shodan
from key import SHODAN_KEY, VIRUS_TOTAL
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from whois import whois


# API key de Shodan (Necesitas obtener tu propia API key en https://www.shodan.io/)
SHODAN_API_KEY = SHODAN_KEY
shodan_api = Shodan(SHODAN_API_KEY)

# Función para hacer solicitudes con reintentos
def get_with_retries(url, headers=None, retries=3, backoff_factor=0.3):
    session = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff_factor, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    try:
        response = session.get(url, headers=headers, timeout=20)
        response.raise_for_status()  # Levanta un error para códigos de estado 4xx y 5xx
        return response
    except requests.RequestException as e:
        print(f"Error retrieving URL: {e}")
        return None

# Función para obtener información de DNS y dominio
def get_domain_info(url):
    domain = url.split('//')[-1].split('/')[0]
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"IP address: {ip_address}")
    except socket.gaierror:
        print(f"Could not resolve {domain}")
        return

    try:
        # Cambiado aquí para usar la importación directa
        from whois import whois
        w = whois(domain)
        print(f"Domain info: {w}")
    except Exception as e:
        print(f"Whois error: {e}")

# Función para escanear puertos abiertos usando nmap
def scan_ports(url):
    domain = url.split('//')[-1].split('/')[0]
    ip_address = socket.gethostbyname(domain)
    nm = nmap.PortScanner()
    nm.scan(ip_address, '1-1024')  # Escanear puertos comunes
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")

# Verificar si el sitio tiene un certificado SSL válido
def check_ssl_certificate(url):
    domain = url.split('//')[-1].split('/')[0]
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            subject = dict(x[0] for x in cert['subject'])
            issued_to = subject['commonName']
            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            print(f"SSL Certificate issued to: {issued_to}")
            print(f"Certificate valid until: {expiry_date}")
            if expiry_date < datetime.now(datetime.UTC):
                print("Warning: SSL certificate is expired!")
            else:
                print("SSL certificate is valid.")
    except Exception as e:
        print(f"SSL Certificate error: {e}")

# Verificar reputación de la URL usando VirusTotal (requiere API key)
def check_url_reputation(url):
    api_key = VIRUS_TOTAL
    headers = {
        "x-apikey": api_key
    }
    response = get_with_retries(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
    if response and response.status_code == 200:
        json_response = response.json()
        print(f"URL Reputation: {json_response['data']['attributes']['last_analysis_stats']}")
    else:
        print(f"Error checking URL reputation: {response.status_code if response else 'No response'}")

# Obtener información del servidor
def get_server_info(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    response = get_with_retries(url, headers=headers)
    if response:
        print(f"Server Headers: {response.headers}")

# Extraer correos electrónicos de la página web
def extract_emails(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    response = get_with_retries(url, headers=headers)
    if response:
        soup = BeautifulSoup(response.content, 'html.parser')
        emails = set()
        for a in soup.find_all('a', href=True):
            if 'mailto:' in a['href']:
                emails.add(a['href'].split(':')[1])
        print(f"Emails found: {emails}")

# Función para buscar información en Shodan
def check_shodan(domain):
    try:
        host = shodan_api.host(socket.gethostbyname(domain))
        print(f"IP: {host['ip_str']}")
        print(f"Organization: {host.get('org', 'n/a')}")
        print(f"Operating System: {host.get('os', 'n/a')}")
        for item in host['data']:
            print(f"Port: {item['port']} - Banner: {item['data']}")
    except Exception as e:
        print(f"Shodan error: {e}")

# Función principal para ejecutar el análisis
def analyze_url(url):
    print(f"Analyzing URL: {url}")
    get_domain_info(url)
    scan_ports(url)
    check_ssl_certificate(url)
    get_server_info(url)
    extract_emails(url)
    check_shodan(url)

# Ejecución del análisis
url = input("Ingrese la URL a analizar: ")
analyze_url(url)