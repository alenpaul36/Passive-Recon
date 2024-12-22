#!/usr/bin/env python3

# Standard library imports
import os
import sys
import argparse
import json
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from pathlib import Path
import socket
import ssl
from urllib.parse import urlparse, quote

# Third-party imports - Core networking
import dns.resolver
import requests
from bs4 import BeautifulSoup
import whois  # Changed from python_whois
from urllib3.exceptions import InsecureRequestWarning
from requests_futures.sessions import FuturesSession

# Third-party imports - OSINT and Security
from github import Github
from github.GithubException import GithubException
import shodan
from censys.search import CensysHosts
import builtwith

# Third-party imports - Utilities
from dotenv import load_dotenv
import yara
import git
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Third-party imports - Console UI
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from colorama import Fore, Style, init
from tqdm import tqdm
from concurrent.futures import wait

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Load environment variables
load_dotenv()

class PassiveRecon:
    def __init__(self, domain, output_dir="reports"):
        """Initialize the PassiveRecon class with domain and output directory."""
        self.domain = domain
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Initialize results dictionary
        self.results = {
            "summary": {
                "domain": domain,
                "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "missing_api_keys": []
            },
            "whois": {},
            "dns": {},
            "ssl": {},
            "security_headers": {},
            "technology_stack": {},
            "credential_leaks": {},
            "github_secrets": {},
            "social_media": {},
            "email_addresses": {},
            "subdomains": {},
            "wayback_data": {},
            "pastebin_leaks": {},
            "google_dorks": {},
            "threat_intel": {}
        }
        
        # Load environment variables
        load_dotenv()
        
        # API Keys
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.hibp_api_key = os.getenv('HIBP_API_KEY')
        self.shodan_api_key = os.getenv('SHODAN_API_KEY')
        self.censys_id = os.getenv('CENSYS_API_ID')
        self.censys_secret = os.getenv('CENSYS_API_SECRET')

        # Initialize API clients
        self.initialize_api_clients()

    def check_api_keys(self):
        """Check which API keys are available and store their status."""
        self.api_keys_status = {
            'GITHUB_TOKEN': bool(os.getenv('GITHUB_TOKEN')),
            'HIBP_API_KEY': bool(os.getenv('HIBP_API_KEY')),
            'SHODAN_API_KEY': bool(os.getenv('SHODAN_API_KEY')),
            'CENSYS_API_ID': bool(os.getenv('CENSYS_API_ID')),
            'CENSYS_API_SECRET': bool(os.getenv('CENSYS_API_SECRET')),
        }
        return self.api_keys_status

    def initialize_api_clients(self):
        """Initialize API clients with environment variables."""
        # GitHub
        if self.github_token:
            self.github = Github(self.github_token)
        
        # Shodan
        if self.shodan_api_key:
            self.shodan = shodan.Shodan(self.shodan_api_key)
        
        # Censys
        if self.censys_id and self.censys_secret:
            self.censys = CensysHosts(api_id=self.censys_id, api_secret=self.censys_secret)

    def print_banner(self):
        banner = f"""
{Fore.RED}
██████╗  █████╗ ███████╗███████╗██╗██╗   ██╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔════╝██╔════╝██║██║   ██║██╔════╝██╔══██╗
██████╔╝███████║███████╗███████╗██║██║   ██║█████╗  ██████╔╝
██╔═══╝ ██╔══██║╚════██║╚════██║██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
██║     ██║  ██║███████║███████║██║ ╚████╔╝ ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
                                                            
        [ Passive Reconnaissance Framework v1.0 ]
        [ Created for Red Team Operations by Alen Paul ]
{Style.RESET_ALL}"""
        print(banner)
        
    def print_section(self, title):
        print(f"\n{Fore.CYAN}[+] {title}{Style.RESET_ALL}")
        print("=" * 60)

    def print_info(self, message):
        print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

    def print_success(self, message):
        print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

    def print_warning(self, message):
        print(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

    def print_error(self, message):
        print(f"{Fore.RED}{message}{Style.RESET_ALL}")

    def get_whois_info(self):
        """Get WHOIS information for the domain."""
        try:
            whois_info = whois.whois(self.domain)
            if whois_info:
                # Format dates consistently
                creation_date = whois_info.creation_date
                expiration_date = whois_info.expiration_date
                
                # Handle list of dates
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]

                # Structure WHOIS data
                self.results["whois"] = {
                    "Domain Name": self.domain,
                    "Registrar": whois_info.registrar,
                    "Creation Date": creation_date,
                    "Creation Age": self.analyze_domain_age(creation_date),
                    "Expiration Date": expiration_date,
                    "Expiration Status": self.analyze_expiration(expiration_date),
                    "Updated Date": whois_info.updated_date,
                    "Name Servers": whois_info.name_servers,
                    "Status": whois_info.status,
                    "Emails": whois_info.emails,
                    "DNSSEC": whois_info.dnssec,
                    "Organization": whois_info.org,
                    "State": whois_info.state,
                    "Country": whois_info.country
                }

                # Remove None values
                self.results["whois"] = {k: v for k, v in self.results["whois"].items() if v is not None}
        except Exception as e:
            self.results["whois"] = {"error": str(e)}

    def get_dns_records(self):
        """Get DNS records for the domain."""
        try:
            resolver = dns.resolver.Resolver()
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            dns_results = {}
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(self.domain, record_type)
                    records = []
                    
                    if record_type == 'MX':
                        for answer in answers:
                            records.append({
                                'preference': answer.preference,
                                'exchange': str(answer.exchange),
                                'description': 'Mail server record',
                                'value': f"{answer.preference} {str(answer.exchange)}"  # For template compatibility
                            })
                    elif record_type == 'SOA':
                        records.append({
                            'mname': str(answers.mname),
                            'rname': str(answers.rname),
                            'serial': answers.serial,
                            'refresh': answers.refresh,
                            'retry': answers.retry,
                            'expire': answers.expire,
                            'minimum': answers.minimum,
                            'description': 'Start of Authority record',
                            'value': f"{str(answers.mname)} {str(answers.rname)} (Serial: {answers.serial})"  # For template
                        })
                    else:
                        for answer in answers:
                            records.append({
                                'value': str(answer),
                                'description': self.get_record_description(record_type)
                            })
                    
                    if records:  # Only add if we found records
                        dns_results[record_type] = records
                        
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.NXDOMAIN:
                    dns_results['error'] = 'Domain does not exist'
                    break
                except Exception as e:
                    dns_results[f"{record_type}_error"] = str(e)
            
            self.results["dns"] = dns_results
            
        except Exception as e:
            self.results["dns"] = {"error": str(e)}

    def get_record_description(self, record_type):
        """Get description for DNS record types."""
        descriptions = {
            'A': 'IPv4 address record - Maps hostname to IP address',
            'AAAA': 'IPv6 address record - Maps hostname to IPv6 address',
            'CNAME': 'Canonical name record - Domain alias',
            'NS': 'Nameserver record - Delegates a DNS zone to use the given authoritative nameservers',
            'TXT': 'Text record - Contains machine-readable data for various services',
            'SOA': 'Start of Authority - Specifies authoritative information about a DNS zone',
            'MX': 'Mail exchange record - Specifies mail servers for accepting email'
        }
        return descriptions.get(record_type, 'Unknown record type')

    def get_ssl_info(self):
        """Get SSL certificate information."""
        self.print_section("SSL Certificate Information")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.results["ssl"] = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert['version'],
                        "serial_number": cert['serialNumber'],
                        "not_before": cert['notBefore'],
                        "not_after": cert['notAfter'],
                    }
                    
                    self.print_info("Certificate Information:")
                    self.print_info("Subject:")
                    for key, value in self.results["ssl"]["subject"].items():
                        self.print_info(f"  {key}: {value}")
                    
                    self.print_info("Issuer:")
                    for key, value in self.results["ssl"]["issuer"].items():
                        self.print_info(f"  {key}: {value}")
                    
                    self.print_info("Validity:")
                    self.print_info(f"  Not Before: {cert['notBefore']}")
                    self.print_info(f"  Not After: {cert['notAfter']}")
                    
            return True
        except ssl.SSLError as e:
            self.print_error(f"SSL Error: {str(e)}")
            return False
        except socket.gaierror as e:
            self.print_error(f"DNS Error: {str(e)}")
            return False
        except Exception as e:
            self.print_error(f"Error getting SSL information: {str(e)}")
            return False

    def get_security_headers(self):
        """Get security headers from the domain."""
        try:
            url = f"https://{self.domain}"
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers

            security_headers = {
                'Strict-Transport-Security': {
                    'value': headers.get('Strict-Transport-Security', 'Not Set'),
                    'description': 'Enforces HTTPS connections',
                    'risk': 'High'
                },
                'Content-Security-Policy': {
                    'value': headers.get('Content-Security-Policy', 'Not Set'),
                    'description': 'Controls resource loading',
                    'risk': 'High'
                },
                'X-Frame-Options': {
                    'value': headers.get('X-Frame-Options', 'Not Set'),
                    'description': 'Prevents clickjacking attacks',
                    'risk': 'High'
                },
                'X-Content-Type-Options': {
                    'value': headers.get('X-Content-Type-Options', 'Not Set'),
                    'description': 'Prevents MIME-type sniffing',
                    'risk': 'Medium'
                },
                'X-XSS-Protection': {
                    'value': headers.get('X-XSS-Protection', 'Not Set'),
                    'description': 'Helps prevent XSS attacks',
                    'risk': 'Medium'
                },
                'Referrer-Policy': {
                    'value': headers.get('Referrer-Policy', 'Not Set'),
                    'description': 'Controls referrer information',
                    'risk': 'Low'
                }
            }

            self.results["security_headers"] = security_headers
        except Exception as e:
            self.results["security_headers"] = {"error": str(e)}

    def get_web_technologies(self):
        """Get web technologies used by the website."""
        self.print_section("Web Technologies")
        try:
            technologies = builtwith.parse(f"https://{self.domain}")
            if technologies:
                self.results["technology_stack"] = technologies
                self.print_info("Detected Technologies:")
                for category, techs in technologies.items():
                    self.print_info(f"{category}:")
                    for tech in techs:
                        self.print_info(f"  {tech}")
                return True
            else:
                self.print_warning("No technologies detected")
                return False
        except Exception as e:
            self.print_error(f"Error analyzing web technologies: {str(e)}")
            return False

    def check_credential_leaks(self):
        """Check for credential leaks using HIBP API."""
        self.print_section("Checking Credential Leaks")
        
        if not os.getenv('HIBP_API_KEY'):
            self.print_warning("HIBP_API_KEY not set. Skipping credential leak check.")
            return
        
        try:
            headers = {
                'hibp-api-key': os.getenv('HIBP_API_KEY'),
                'user-agent': 'PassiveRecon-Tool'
            }
            
            self.print_info("Querying Have I Been Pwned API...")
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breaches",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                breaches = response.json()
                domain_breaches = [
                    breach for breach in breaches
                    if self.domain.lower() in breach.get('Domain', '').lower()
                ]
                
                self.results["credential_leaks"] = {
                    'total_breaches': len(domain_breaches),
                    'breaches': domain_breaches
                }
                
                if domain_breaches:
                    self.print_error(f"Found {len(domain_breaches)} breaches!")
                    for breach in domain_breaches:
                        self.print_info(f"Breach: {breach['Name']}")
                        self.print_info(f"  Date: {breach['BreachDate']}")
                        self.print_info(f"  Accounts: {breach['PwnCount']:,}")
                        self.print_info(f"  Data: {', '.join(breach['DataClasses'])}")
                else:
                    self.print_info("No breaches found")
                    
                return True
            else:
                self.print_error(f"HIBP API returned status code {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.print_error(f"Request Error: {str(e)}")
            return False
        except Exception as e:
            self.print_error(f"Error checking credential leaks: {str(e)}")
            return False

    def check_github_exposure(self):
        """Check for exposed secrets and sensitive information in GitHub repositories"""
        self.print_section("Checking GitHub for Exposed Secrets")
        
        # Define YARA rules for secret detection
        yara_rules = """
        rule aws_key {
            strings:
                $aws_key = /AKIA[0-9A-Z]{16}/
                $aws_secret = /[0-9a-zA-Z/+]{40}/
            condition:
                any of them
        }
        
        rule private_key {
            strings:
                $begin_private = "-----BEGIN PRIVATE KEY-----"
                $begin_rsa = "-----BEGIN RSA PRIVATE KEY-----"
                $begin_ssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
            condition:
                any of them
        }
        
        rule api_token {
            strings:
                $github = /gh[pousr]_[A-Za-z0-9_]{36}/
                $google = /AIza[0-9A-Za-z\\-_]{35}/
                $firebase = /.*firebaseio\\.com/
            condition:
                any of them
        }
        
        rule sensitive_info {
            strings:
                $password_url = /[a-zA-Z]{3,10}:\\/\\/[^/\\s:@]*?:[^/\\s:@]*@[^/\\s:@]*/
                $auth_header = /Authorization: Bearer [0-9a-zA-Z\\-\\._~\\+/]+=*/
            condition:
                any of them
        }
        """
        
        try:
            # Initialize GitHub API
            github_token = os.getenv('GITHUB_TOKEN')
            if not github_token:
                self.print_warning("GITHUB_TOKEN not set. Limited functionality available.")
                return
                
            g = Github(github_token)
            
            # Compile YARA rules
            rules = yara.compile(source=yara_rules)
            
            # Search GitHub for domain-related repositories
            query = f'"{self.domain}" OR {self.domain}'
            repos = g.search_code(query)
            
            findings = {}
            total_repos = 0
            
            with Progress() as progress:
                repos_list = list(repos)
                total_repos = len(repos_list)
                
                task = progress.add_task("[cyan]Scanning GitHub repositories...", total=total_repos)
                
                for repo_file in repos_list:
                    try:
                        repo = repo_file.repository
                        file_content = repo_file.decoded_content.decode('utf-8')
                        
                        # Scan content with YARA rules
                        matches = rules.match(data=file_content)
                        
                        if matches:
                            if repo.full_name not in findings:
                                findings[repo.full_name] = []
                            
                            for match in matches:
                                finding = {
                                    'type': match.rule,
                                    'file': repo_file.path,
                                    'line': file_content.count('\n', 0, match.strings[0][0]) + 1,
                                    'url': repo_file.html_url,
                                    'repo_url': repo.html_url,
                                    'last_modified': repo_file.last_modified
                                }
                                
                                findings[repo.full_name].append(finding)
                                
                                self.print_error(f"Found potential {match.rule} in:")
                                self.print_info(f"  Repository: {repo.full_name}")
                                self.print_info(f"  File: {repo_file.path}")
                                self.print_info(f"  Line: {finding['line']}")
                                self.print_info(f"  URL: {repo_file.html_url}")
                        
                    except Exception as e:
                        self.print_warning(f"Warning: Error processing {repo_file.repository.full_name}: {str(e)}")
                    
                    progress.update(task, advance=1)
                    time.sleep(2)  # Rate limiting
            
            self.results["github_secrets"] = {
                "total_repositories_scanned": total_repos,
                "findings": findings
            }
            
            if findings:
                self.print_error(f"Found {len(findings)} repositories with potential secrets!")
            else:
                self.print_info("No secrets found in public repositories.")
                
        except Exception as e:
            self.print_error(f"Error scanning GitHub: {str(e)}")
            self.results["github_secrets"]["error"] = str(e)

    def print_summary(self):
        """Print a summary of all reconnaissance findings."""
        # Check API keys first
        self.check_api_keys()
        
        print("\n" + "=" * 60)
        
        # WHOIS Information (No API required)
        print(f"\n{Fore.CYAN}[+] WHOIS Information{Style.RESET_ALL}")
        print("=" * 60)
        if self.results.get('whois'):
            if 'error' in self.results['whois']:
                print(f"{Fore.RED}[×] Error: {self.results['whois']['error']}{Style.RESET_ALL}")
            else:
                for key, value in self.results['whois'].items():
                    if isinstance(value, list):
                        print(f"\n{key}:")
                        for item in value:
                            print(f"    - {item}")
                    else:
                        print(f"{key}: {value}")
        else:
            print(f"{Fore.YELLOW}[!] No WHOIS information available. Possible reasons:")
            print("    - Domain does not exist")
            print("    - WHOIS server not responding")
            print("    - Rate limiting from WHOIS server")
            print(f"{Style.RESET_ALL}")

        # DNS Records (No API required)
        print(f"\n{Fore.CYAN}[+] DNS Records{Style.RESET_ALL}")
        print("=" * 60)
        if self.results.get('dns'):
            if 'error' in self.results['dns']:
                print(f"{Fore.RED}[×] Error: {self.results['dns']['error']}{Style.RESET_ALL}")
            else:
                for record_type, records in self.results['dns'].items():
                    if not record_type.endswith('_error'):
                        print(f"\n{record_type} Records:")
                        if record_type == 'MX':
                            for record in records:
                                print(f"    - Priority: {record['preference']}, Server: {record['exchange']}")
                        elif record_type == 'SOA':
                            for record in records:
                                print(f"    - Primary NS: {record['mname']}")
                                print(f"    - Email: {record['rname']}")
                                print(f"    - Serial: {record['serial']}")
                        else:
                            for record in records:
                                print(f"    - {record['value']} ({record['description']})")
                    else:
                        print(f"{Fore.YELLOW}[!] Error getting {record_type[:-6]} records: {records}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No DNS records found. Possible reasons:")
            print("    - Domain does not exist")
            print("    - DNS resolution failed")
            print("    - No DNS records of queried types")
            print(f"{Style.RESET_ALL}")

        # Data Breaches (Requires HIBP API Key)
        print(f"\n{Fore.CYAN}[+] Data Breaches{Style.RESET_ALL}")
        print("=" * 60)
        if not self.api_keys_status['HIBP_API_KEY']:
            print(f"{Fore.YELLOW}[!] Skipped: HIBP_API_KEY not configured{Style.RESET_ALL}")
        elif self.results.get('credential_leaks'):
            if isinstance(self.results['credential_leaks'], dict) and 'error' in self.results['credential_leaks']:
                print(f"{Fore.RED}[×] Error: {self.results['credential_leaks']['error']}{Style.RESET_ALL}")
            else:
                for breach in self.results['credential_leaks']:
                    print(f"\n{Fore.RED}[!] Breach Detected:{Style.RESET_ALL}")
                    print(f"Name: {breach.get('Name', 'Unknown')}")
                    print(f"Date: {breach.get('BreachDate', 'Unknown')}")
                    print(f"Accounts affected: {breach.get('PwnCount', 'Unknown')}")
                    if breach.get('DataClasses'):
                        print("Compromised data types:")
                        for data_type in breach['DataClasses']:
                            print(f"    - {data_type}")
                    print(f"Description: {breach.get('Description', 'No description available')}")
        else:
            print(f"{Fore.GREEN}[+] No data breaches found for this domain{Style.RESET_ALL}")

        # GitHub Exposure (Requires GitHub Token)
        print(f"\n{Fore.CYAN}[+] GitHub Exposure{Style.RESET_ALL}")
        print("=" * 60)
        if not self.api_keys_status['GITHUB_TOKEN']:
            print(f"{Fore.YELLOW}[!] Skipped: GITHUB_TOKEN not configured{Style.RESET_ALL}")
        elif self.results.get('github_secrets'):
            if isinstance(self.results['github_secrets'], dict) and 'error' in self.results['github_secrets']:
                print(f"{Fore.RED}[×] Error: {self.results['github_secrets']['error']}{Style.RESET_ALL}")
            else:
                for repo in self.results['github_secrets']:
                    print(f"\nRepository: {repo.get('name', 'Unknown')}")
                    if repo.get('findings'):
                        for finding in repo['findings']:
                            print(f"{Fore.RED}[!] Found:{Style.RESET_ALL}")
                            print(f"    Type: {finding.get('type', 'Unknown')}")
                            print(f"    File: {finding.get('file', 'Unknown')}")
                            print(f"    Line: {finding.get('line', 'Unknown')}")
        else:
            print(f"{Fore.GREEN}[+] No sensitive data found in GitHub repositories{Style.RESET_ALL}")

        # Shodan Information (Requires Shodan API Key)
        print(f"\n{Fore.CYAN}[+] Shodan Information{Style.RESET_ALL}")
        print("=" * 60)
        if not self.api_keys_status['SHODAN_API_KEY']:
            print(f"{Fore.YELLOW}[!] Skipped: SHODAN_API_KEY not configured{Style.RESET_ALL}")
        elif self.results.get('shodan'):
            if isinstance(self.results['shodan'], dict) and 'error' in self.results['shodan']:
                print(f"{Fore.RED}[×] Error: {self.results['shodan']['error']}{Style.RESET_ALL}")
            else:
                for finding in self.results['shodan']:
                    print(f"\nIP: {finding.get('ip_str', 'Unknown')}")
                    print(f"Open Ports: {', '.join(map(str, finding.get('ports', [])))}")
                    if finding.get('vulns'):
                        print("Vulnerabilities:")
                        for vuln in finding['vulns']:
                            print(f"    - {vuln}")
        else:
            print(f"{Fore.GREEN}[+] No Shodan findings for this domain{Style.RESET_ALL}")

        # Censys Information (Requires Censys API Keys)
        print(f"\n{Fore.CYAN}[+] Censys Information{Style.RESET_ALL}")
        print("=" * 60)
        if not (self.api_keys_status['CENSYS_API_ID'] and self.api_keys_status['CENSYS_API_SECRET']):
            print(f"{Fore.YELLOW}[!] Skipped: CENSYS_API_ID and/or CENSYS_API_SECRET not configured{Style.RESET_ALL}")
        elif self.results.get('censys'):
            if isinstance(self.results['censys'], dict) and 'error' in self.results['censys']:
                print(f"{Fore.RED}[×] Error: {self.results['censys']['error']}{Style.RESET_ALL}")
            else:
                for finding in self.results['censys']:
                    print(f"\nIP: {finding.get('ip', 'Unknown')}")
                    print(f"Protocols: {', '.join(finding.get('protocols', []))}")
                    if finding.get('ports'):
                        print("Open Ports:")
                        for port in finding['ports']:
                            print(f"    - {port}")
        else:
            print(f"{Fore.GREEN}[+] No Censys findings for this domain{Style.RESET_ALL}")

        # Google Dorks
        print(f"\n{Fore.CYAN}[+] Google Dorks Findings{Style.RESET_ALL}")
        print("=" * 60)
        if self.results.get('google_dorks'):
            if isinstance(self.results['google_dorks'], dict) and 'error' in self.results['google_dorks']:
                print(f"{Fore.RED}[×] Error: {self.results['google_dorks']['error']}{Style.RESET_ALL}")
            else:
                for finding in self.results['google_dorks']:
                    print(f"\n{Fore.YELLOW}[!] Sensitive Information Found:{Style.RESET_ALL}")
                    print(f"Query: {finding['query']}")
                    print(f"Description: {finding['description']}")
                    print(f"Search URL: {finding['url']}")
        else:
            print(f"{Fore.GREEN}[+] No sensitive information found through Google Dorks{Style.RESET_ALL}")

        # Threat Intelligence
        print(f"\n{Fore.CYAN}[+] Threat Intelligence{Style.RESET_ALL}")
        print("=" * 60)
        if self.results.get('threat_intel'):
            if isinstance(self.results['threat_intel'], dict) and 'error' in self.results['threat_intel']:
                print(f"{Fore.RED}[×] Error: {self.results['threat_intel']['error']}{Style.RESET_ALL}")
            else:
                for finding in self.results['threat_intel']:
                    if isinstance(finding, dict):
                        print(f"\n{Fore.RED}[!] Threat Found:{Style.RESET_ALL}")
                        print(f"Type: {finding.get('type', 'Unknown')}")
                        print(f"Severity: {finding.get('severity', 'Unknown')}")
                        print(f"Description: {finding.get('description', 'N/A')}")
                        if finding.get('indicators'):
                            print("Indicators:")
                            for indicator in finding['indicators']:
                                print(f"    - {indicator}")
                    else:
                        print(f"Finding: {finding}")
        else:
            print(f"{Fore.GREEN}[+] No threats detected{Style.RESET_ALL}")

    def check_social_media(self):
        """Check social media presence."""
        self.print_section("Social Media Reconnaissance")
        platforms = {
            'LinkedIn': f'https://linkedin.com/company/{self.domain}',
            'Twitter': f'https://twitter.com/{self.domain}',
            'Facebook': f'https://facebook.com/{self.domain}',
            'Instagram': f'https://instagram.com/{self.domain}',
            'GitHub': f'https://github.com/{self.domain}'
        }
        
        results = {}
        for platform, url in platforms.items():
            try:
                response = requests.get(url)
                results[platform] = response.status_code == 200
                if results[platform]:
                    self.print_info(f"Found {platform} presence: {url}")
            except:
                results[platform] = False
        
        self.results["social_media"] = results
        return True

    def check_wayback_machine(self):
        """Check Wayback Machine for historical data."""
        self.print_section("Wayback Machine Analysis")
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&limit=1000"  # Limit results
            response = requests.get(url, timeout=10)  # 10 seconds timeout
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:  # First row is header
                    self.results["wayback_data"] = data[1:]
                    self.print_info(f"Found {len(data)-1} snapshots in Wayback Machine")
                    return True
            return False
        except requests.Timeout:
            self.print_warning("Wayback Machine check timed out")
            return False
        except Exception as e:
            self.print_error(f"Error checking Wayback Machine: {str(e)}")
            return False

    def check_pastebin(self):
        """Check Pastebin for leaks (requires API key for full functionality)."""
        self.print_section("Pastebin Leaks")
        # Note: This is a placeholder. Full implementation would require Pastebin API
        self.print_warning("Pastebin API required for full functionality")
        return True

    def check_google_dorks(self):
        """Check for sensitive information using Google dorks."""
        try:
            # Define common Google dorks for finding sensitive information
            dorks = [
                {
                    "query": f"site:{self.domain} filetype:pdf",
                    "description": "PDF documents that might contain sensitive information"
                },
                {
                    "query": f"site:{self.domain} filetype:doc OR filetype:docx",
                    "description": "Microsoft Word documents that might contain sensitive information"
                },
                {
                    "query": f"site:{self.domain} filetype:xls OR filetype:xlsx",
                    "description": "Excel spreadsheets that might contain sensitive information"
                },
                {
                    "query": f"site:{self.domain} inurl:admin OR inurl:login",
                    "description": "Admin or login pages"
                },
                {
                    "query": f"site:{self.domain} inurl:config OR inurl:setup",
                    "description": "Configuration or setup pages"
                },
                {
                    "query": f"site:{self.domain} ext:sql OR ext:db OR ext:backup",
                    "description": "Database files or backups"
                },
                {
                    "query": f"site:{self.domain} intext:password OR intext:username",
                    "description": "Pages containing password or username information"
                }
            ]

            findings = []
            for dork in dorks:
                # Create a search URL (Note: In a real tool, you'd want to use an API)
                search_url = f"https://www.google.com/search?q={quote(dork['query'])}"
                findings.append({
                    "query": dork["query"],
                    "url": search_url,
                    "description": dork["description"]
                })

            self.results["google_dorks"] = findings

        except Exception as e:
            self.results["google_dorks"] = {"error": str(e)}

    def check_threat_intel(self):
        """Check various threat intelligence sources."""
        self.print_section("Threat Intelligence")
        try:
            # Check VirusTotal (requires API key)
            self.print_warning("VirusTotal API key required for full functionality")
            
            # Check AbuseIPDB (requires API key)
            self.print_warning("AbuseIPDB API key required for full functionality")
            
            # Check AlienVault OTX (requires API key)
            self.print_warning("AlienVault OTX API key required for full functionality")
            
            return True
        except Exception as e:
            self.print_error(f"Error checking threat intelligence: {str(e)}")
            return False

    def generate_report(self):
        """Generate an HTML report of the findings."""
        try:
            env = Environment(
                loader=FileSystemLoader('templates'),
                autoescape=select_autoescape(['html', 'xml'])
            )
            template = env.get_template('report_template.html')

            # Process and format the data for the template
            report_data = {
                'domain': self.domain,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                
                # WHOIS Information
                'whois': self.results.get('whois', {}),
                
                # DNS Records - Ensure proper structure
                'dns': self.results.get('dns', {}),
                
                # Security Headers - Count missing headers
                'security_headers': {
                    'headers': self.results.get('security_headers', {}),
                    'missing_count': sum(1 for v in self.results.get('security_headers', {}).values() if v.get('value') == "Not Set")
                },
                
                # Technology Stack
                'technology_stack': self.results.get('technology_stack', {}),
                
                # Data Breaches
                'credential_leaks': self.results.get('credential_leaks', []),
                
                # GitHub Exposures
                'github_secrets': self.results.get('github_secrets', []),
                
                # Google Dorks
                'google_dorks': self.results.get('google_dorks', []),
                
                # Threat Intelligence
                'threat_intel': self.results.get('threat_intel', []),
                
                # Risk Metrics
                'risk_metrics': {
                    'high_risks': [],
                    'medium_risks': [],
                    'low_risks': []
                }
            }

            # Calculate risk metrics
            if self.results.get('security_headers'):
                missing_critical = ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']
                for header in missing_critical:
                    if self.results['security_headers'].get(header, {}).get('value') == "Not Set":
                        report_data['risk_metrics']['high_risks'].append(
                            f"Missing critical security header: {header}")

            if self.results.get('credential_leaks'):
                report_data['risk_metrics']['high_risks'].append(
                    f"Found {len(self.results['credential_leaks'])} data breaches")

            if self.results.get('github_secrets'):
                report_data['risk_metrics']['high_risks'].append(
                    f"Found sensitive data in {len(self.results['github_secrets'])} GitHub repositories")

            # Generate HTML report
            html_content = template.render(**report_data)

            # Save the report
            report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
            os.makedirs(report_path, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = os.path.join(report_path, f'recon_report_{self.domain}_{timestamp}.html')
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Fore.GREEN}[+] Report generated: {report_file}{Style.RESET_ALL}")
            return report_file

        except Exception as e:
            print(f"{Fore.RED}[×] Error generating report: {str(e)}{Style.RESET_ALL}")
            return None

    def analyze_domain_age(self, creation_date):
        """Analyze domain age and provide risk assessment."""
        if not creation_date:
            return "Unknown"
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        age = (datetime.now() - creation_date).days
        
        if age < 30:
            return "Very New (High Risk)"
        elif age < 180:
            return "Recent (Medium Risk)"
        elif age < 365:
            return "Less than a year (Low Risk)"
        else:
            return f"Established ({age // 365} years old)"

    def analyze_expiration(self, expiration_date):
        """Analyze domain expiration and provide risk assessment."""
        if not expiration_date:
            return "Unknown"
        
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        days_until = (expiration_date - datetime.now()).days
        
        if days_until < 30:
            return "Critical - Expires soon"
        elif days_until < 90:
            return "Warning - Expires in less than 3 months"
        else:
            return f"Valid for {days_until // 30} months"

    def run_all(self):
        """Run all reconnaissance modules."""
        self.print_banner()
        
        # Check API keys before starting
        self.check_api_keys()
        
        # Define functions with their proper names
        functions = [
            (self.get_whois_info, "WHOIS Lookup"),
            (self.get_dns_records, "DNS Records"),
            (self.get_ssl_info, "SSL Certificate"),
            (self.get_security_headers, "Security Headers"),
            (self.get_web_technologies, "Web Technologies"),
            (self.check_credential_leaks, "Credential Leaks"),
            (self.check_github_exposure, "GitHub Exposure"),
            (self.check_social_media, "Social Media"),
            (self.check_wayback_machine, "Wayback Machine"),
            (self.check_pastebin, "Pastebin"),
            (self.check_google_dorks, "Google Dorks"),
            (self.check_threat_intel, "Threat Intel")
        ]
        
        # Print initial status
        print(f"\n{Fore.CYAN}[*] Target: {self.domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Starting reconnaissance...{Style.RESET_ALL}\n")
        
        try:
            # Run functions in parallel with maximum 3 concurrent tasks
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                for func, name in functions:
                    future = executor.submit(func)
                    futures.append((future, name))
                
                # Wait for completion
                for future, name in futures:
                    try:
                        future.result(timeout=30)
                        print(f"{Fore.GREEN}[+] {name:<20} Complete{Style.RESET_ALL}")
                    except TimeoutError:
                        print(f"{Fore.YELLOW}[!] {name:<20} Timeout{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}[×] {name:<20} Failed{Style.RESET_ALL}")
                        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Reconnaissance interrupted by user{Style.RESET_ALL}")
            return
        except Exception as e:
            print(f"\n{Fore.RED}[×] Error during reconnaissance: {str(e)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Reconnaissance completed{Style.RESET_ALL}\n")
        
        # Generate summary and report
        self.print_summary()
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(description="Passive Reconnaissance Tool for Kali Linux")
    parser.add_argument("domain", help="Target domain to perform reconnaissance on")
    parser.add_argument("-o", "--output-dir", default="reports", help="Output directory for reports (default: reports)")
    parser.add_argument("-m", "--modules", help="Specific modules to run (comma-separated). Available: dns,ssl,github,whois,headers,web,shodan,censys")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    try:
        recon = PassiveRecon(args.domain, args.output_dir)
        
        if args.modules:
            modules = args.modules.split(',')
            module_map = {
                'dns': recon.get_dns_records,
                'ssl': recon.get_ssl_info,
                'github': recon.check_github_exposure,
                'whois': recon.get_whois_info,
                'headers': recon.get_security_headers,
                'web': recon.get_web_technologies,
                'shodan': recon.check_shodan,
                'censys': recon.check_censys
            }
            
            for module in modules:
                if module in module_map:
                    module_map[module]()
                else:
                    print(f"{Fore.RED}Unknown module: {module}{Style.RESET_ALL}")
        else:
            recon.run_all()
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Reconnaissance interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()