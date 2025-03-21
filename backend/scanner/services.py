import re
import ssl
import socket
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from bs4 import BeautifulSoup
from scanner.models import Scan, Vulnerability  # Added Vulnerability import here

class ScannerService:
    def __init__(self, scan_id=None):
        """Initialize the scanner service with an optional scan_id."""
        self.scan_id = scan_id
    
    def scan_website(self, url):
        """Perform a comprehensive security scan of the website."""
        try:
            # Update scan status
            self.update_scan_status(status="in_progress", progress=10, current_stage="Initializing scan...")
            
            # Basic validation and normalization of the URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            # Create a session for consistent requests
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            
            # Fetch the main page
            self.update_scan_status(progress=15, current_stage="Connecting to target website...")
            response = session.get(url, timeout=10, verify=False)
            
            # Initialize vulnerabilities list
            vulnerabilities = []
            
            # 1. Check for HTTP Security Headers (20%)
            self.update_scan_status(progress=20, current_stage="Checking HTTP security headers...")
            header_vulnerabilities = self.check_security_headers(response.headers, url)
            vulnerabilities.extend(header_vulnerabilities)
            
            # 2. Check for clickjacking protection
            clickjacking_vulnerabilities = self.check_for_clickjacking(response.headers, url)
            vulnerabilities.extend(clickjacking_vulnerabilities)
            
            # 3. Check for CORS misconfiguration
            cors_vulnerabilities = self.check_for_cors_misconfiguration(response.headers, url)
            vulnerabilities.extend(cors_vulnerabilities)
            
            # 4. Check for server information disclosure
            server_info_vulnerabilities = self.check_for_server_information(response.headers, url)
            vulnerabilities.extend(server_info_vulnerabilities)
            
            # 5. Check for insecure cookies
            cookie_vulnerabilities = self.check_for_insecure_cookies(response.headers, url)
            vulnerabilities.extend(cookie_vulnerabilities)
            
            # 6. Crawl the website to discover pages (30%)
            self.update_scan_status(progress=30, current_stage="Crawling website for pages...")
            pages = self.crawl_website(session, url, max_pages=10)
            
            # 7. Check for common vulnerabilities across all pages (50%)
            self.update_scan_status(progress=50, current_stage="Scanning for vulnerabilities...")
            for page_url in pages:
                # Check for XSS vulnerabilities
                xss_vulnerabilities = self.check_for_xss(session, page_url)
                vulnerabilities.extend(xss_vulnerabilities)
                
                # Check for SQL Injection vulnerabilities
                sqli_vulnerabilities = self.check_for_sql_injection(session, page_url)
                vulnerabilities.extend(sqli_vulnerabilities)
                
                # Check for CSRF vulnerabilities
                csrf_vulnerabilities = self.check_for_csrf(session, page_url)
                vulnerabilities.extend(csrf_vulnerabilities)
                
                # Check for open redirects
                redirect_vulnerabilities = self.check_for_open_redirects(session, page_url)
                vulnerabilities.extend(redirect_vulnerabilities)
            
            # 8. Check for SSL/TLS issues (70%)
            self.update_scan_status(progress=70, current_stage="Analyzing SSL/TLS configuration...")
            ssl_vulnerabilities = self.check_ssl_tls(url)
            vulnerabilities.extend(ssl_vulnerabilities)
            
            # 9. Check for outdated software and CMS (80%)
            self.update_scan_status(progress=80, current_stage="Detecting software versions...")
            software_vulnerabilities = self.check_outdated_software(response.text, url)
            vulnerabilities.extend(software_vulnerabilities)
            
            # 10. Check for sensitive data exposure (90%)
            self.update_scan_status(progress=90, current_stage="Checking for sensitive data exposure...")
            sensitive_data_vulnerabilities = self.check_sensitive_data_exposure(response.text, url)
            vulnerabilities.extend(sensitive_data_vulnerabilities)
            
            # Generate summary
            summary = self.generate_summary(vulnerabilities)
            
            # Update scan with results
            self.update_scan_status(
                status="completed", 
                progress=100, 
                current_stage="Scan completed",
                vulnerabilities=vulnerabilities,
                summary=summary
            )
            
            return vulnerabilities
            
        except Exception as e:
            self.update_scan_status(status="failed", progress=0, current_stage=f"Error: {str(e)}")
            raise
    
    def check_security_headers(self, headers, url):
        """Check for missing or misconfigured security headers."""
        vulnerabilities = []
        
        # Important security headers to check
        security_headers = {
            'Strict-Transport-Security': {
                'missing_message': 'Missing HSTS header which helps protect against protocol downgrade attacks.',
                'remediation': 'Add the Strict-Transport-Security header with a long max-age directive.'
            },
            'Content-Security-Policy': {
                'missing_message': 'Missing Content Security Policy header which helps mitigate XSS attacks.',
                'remediation': 'Implement a Content Security Policy that restricts resource loading to trusted sources.'
            },
            'X-Content-Type-Options': {
                'missing_message': 'Missing X-Content-Type-Options header which prevents MIME type sniffing.',
                'remediation': 'Add the X-Content-Type-Options header with the "nosniff" value.'
            },
            'X-Frame-Options': {
                'missing_message': 'Missing X-Frame-Options header which prevents clickjacking attacks.',
                'remediation': 'Add the X-Frame-Options header with "DENY" or "SAMEORIGIN" value.'
            },
            'Referrer-Policy': {
                'missing_message': 'Missing Referrer-Policy header which controls how much referrer information is included with requests.',
                'remediation': 'Add a Referrer-Policy header with an appropriate value like "strict-origin-when-cross-origin".'
            }
        }
        
        for header, info in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'name': f'Missing {header} Header',
                    'description': info['missing_message'],
                    'severity': 'medium' if header == 'Strict-Transport-Security' or header == 'Content-Security-Policy' else 'low',
                    'affected_url': url,
                    'remediation': info['remediation']
                })
        
        return vulnerabilities
    
    def crawl_website(self, session, base_url, max_pages=10):
        """Crawl the website to discover pages."""
        discovered_urls = set([base_url])
        urls_to_visit = [base_url]
        visited_urls = set()
        
        while urls_to_visit and len(visited_urls) < max_pages:
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls:
                continue
                
            try:
                response = session.get(current_url, timeout=5)
                visited_urls.add(current_url)
                
                # Parse the HTML content
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    
                    # Handle relative URLs
                    if href.startswith('/'):
                        href = urljoin(base_url, href)
                    elif not href.startswith(('http://', 'https://')):
                        href = urljoin(current_url, href)
                    
                    # Only add URLs from the same domain
                    if urlparse(href).netloc == urlparse(base_url).netloc and href not in discovered_urls:
                        discovered_urls.add(href)
                        urls_to_visit.append(href)
            except:
                # Skip any errors during crawling
                pass
        
        return list(visited_urls)
    
    def check_for_xss(self, session, url):
        """Check for potential XSS vulnerabilities."""
        vulnerabilities = []
        
        # Extract forms from the page
        try:
            response = session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if forms:
                # If forms are found, there's a potential for XSS
                vulnerabilities.append({
                    'name': 'Cross-Site Scripting (XSS)',
                    'description': 'The page contains forms that might be vulnerable to XSS attacks if user input is not properly sanitized.',
                    'severity': 'high',
                    'affected_url': url,
                    'remediation': 'Implement proper input validation and output encoding. Use Content-Security-Policy and modern frameworks that automatically escape output.'
                })
                
            # Check for reflected parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                for param, value in query_params.items():
                    if value[0] in response.text:
                        vulnerabilities.append({
                            'name': 'Reflected Parameter',
                            'description': f'The parameter "{param}" is reflected in the page response, which might lead to Reflected XSS if not properly sanitized.',
                            'severity': 'medium',
                            'affected_url': url,
                            'remediation': 'Ensure all user-supplied data is properly sanitized before being included in the response.'
                        })
        except:
            pass
            
        return vulnerabilities
    
    def check_for_sql_injection(self, session, url):
        """Check for potential SQL Injection vulnerabilities."""
        vulnerabilities = []
        
        # Extract forms and parameters
        try:
            response = session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if forms:
                # If forms with input fields are found, there's a potential for SQL Injection
                for form in forms:
                    inputs = form.find_all('input')
                    if inputs:
                        vulnerabilities.append({
                            'name': 'Potential SQL Injection',
                            'description': 'The page contains forms with input fields that might be vulnerable to SQL Injection if user input is not properly sanitized.',
                            'severity': 'high',
                            'affected_url': url,
                            'remediation': 'Use parameterized queries or prepared statements. Implement proper input validation and use an ORM if possible.'
                        })
                        break
        except:
            pass
            
        return vulnerabilities
    
    def check_for_csrf(self, session, url):
        """Check for CSRF vulnerabilities."""
        vulnerabilities = []
        
        try:
            response = session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                # Check if the form has a CSRF token
                csrf_tokens = form.find_all('input', attrs={'name': re.compile('csrf|token', re.I)})
                if not csrf_tokens:
                    vulnerabilities.append({
                        'name': 'Cross-Site Request Forgery (CSRF)',
                        'description': 'A form was found without a CSRF token, which could make it vulnerable to CSRF attacks.',
                        'severity': 'medium',
                        'affected_url': url,
                        'remediation': 'Implement CSRF tokens for all forms and validate them on the server side.'
                    })
        except:
            pass
            
        return vulnerabilities
    
    def check_for_open_redirects(self, session, url):
        """Check for open redirect vulnerabilities."""
        vulnerabilities = []
        
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            redirect_params = ['redirect', 'url', 'next', 'return', 'returnUrl', 'returnTo', 'goto', 'continue']
            
            for param in redirect_params:
                if param in query_params:
                    vulnerabilities.append({
                        'name': 'Open Redirect',
                        'description': f'The page uses a "{param}" parameter which might be vulnerable to open redirect attacks if not properly validated.',
                        'severity': 'medium',
                        'affected_url': url,
                        'remediation': 'Validate all redirect URLs against a whitelist or ensure they are relative URLs.'
                    })
                    
        return vulnerabilities
    
    def check_ssl_tls(self, url):
        """Check for SSL/TLS vulnerabilities."""
        vulnerabilities = []
        
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            
            # Check if the site is using HTTPS
            if parsed_url.scheme != 'https':
                vulnerabilities.append({
                    'name': 'Insecure Protocol',
                    'description': 'The website is using HTTP instead of HTTPS, which does not encrypt data in transit.',
                    'severity': 'high',
                    'affected_url': url,
                    'remediation': 'Implement HTTPS across the entire website and redirect all HTTP traffic to HTTPS.'
                })
            else:
                # Check SSL certificate
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check certificate expiration
                        expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if expires < datetime.now() + timedelta(days=30):
                            vulnerabilities.append({
                                'name': 'SSL Certificate Expiring Soon',
                                'description': f'The SSL certificate will expire on {expires.strftime("%Y-%m-%d")}.',
                                'severity': 'medium',
                                'affected_url': url,
                                'remediation': 'Renew the SSL certificate before it expires.'
                            })
        except:
            # If we can't check the SSL, assume there might be an issue
            vulnerabilities.append({
                'name': 'SSL/TLS Configuration Issue',
                'description': 'Could not verify the SSL/TLS configuration of the website.',
                'severity': 'medium',
                'affected_url': url,
                'remediation': 'Ensure the website has a valid SSL certificate and is properly configured for secure connections.'
            })
            
        return vulnerabilities
    
    def check_outdated_software(self, html_content, url):
        """Check for outdated software or CMS versions."""
        vulnerabilities = []
        
        # Check for common CMS signatures
        cms_patterns = {
            'WordPress': {
                'pattern': re.compile(r'wp-content|wordpress|wp-includes', re.I),
                'version_pattern': re.compile(r'<meta name="generator" content="WordPress ([0-9.]+)"', re.I)
            },
            'Joomla': {
                'pattern': re.compile(r'joomla!|<script src="[^"]*media/jui/js/jquery.min.js', re.I),
                'version_pattern': re.compile(r'<meta name="generator" content="Joomla! ([0-9.]+)"', re.I)
            },
            'Drupal': {
                'pattern': re.compile(r'drupal|sites/all|sites/default', re.I),
                'version_pattern': re.compile(r'<meta name="Generator" content="Drupal ([0-9.]+)"', re.I)
            }
        }
        
        for cms, patterns in cms_patterns.items():
            if patterns['pattern'].search(html_content):
                version_match = patterns['version_pattern'].search(html_content)
                version = version_match.group(1) if version_match else "unknown"
                
                vulnerabilities.append({
                    'name': f'Detected {cms} CMS',
                    'description': f'The website is running {cms} version {version}, which may contain known vulnerabilities if not updated.',
                    'severity': 'medium',
                    'affected_url': url,
                    'remediation': f'Keep {cms} updated to the latest version and apply security patches promptly.'
                })
        
        # Check for JavaScript libraries
        js_libraries = {
            'jQuery': re.compile(r'jquery[.-]([0-9.]+)\.min\.js', re.I),
            'Bootstrap': re.compile(r'bootstrap[.-]([0-9.]+)\.min\.js', re.I),
            'Angular': re.compile(r'angular[.-]([0-9.]+)\.min\.js', re.I),
            'React': re.compile(r'react[.-]([0-9.]+)\.min\.js', re.I)
        }
        
        for lib, pattern in js_libraries.items():
            match = pattern.search(html_content)
            if match:
                version = match.group(1)
                vulnerabilities.append({
                    'name': f'Detected {lib} Library',
                    'description': f'The website is using {lib} version {version}, which may contain known vulnerabilities if outdated.',
                    'severity': 'low',
                    'affected_url': url,
                    'remediation': f'Keep {lib} updated to the latest version to avoid known security vulnerabilities.'
                })
                
        return vulnerabilities
    
    def check_sensitive_data_exposure(self, html_content, url):
        """Check for sensitive data exposure in the page content."""
        vulnerabilities = []
        
        # Check for email addresses
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        emails = email_pattern.findall(html_content)
        if emails:
            vulnerabilities.append({
                'name': 'Email Address Exposure',
                'description': f'Found {len(emails)} email address(es) exposed in the page content, which could be harvested by spammers.',
                'severity': 'low',
                'affected_url': url,
                'remediation': 'Obfuscate email addresses or use contact forms instead of displaying email addresses directly.'
            })
        
        # Check for possible API keys and tokens
        api_key_patterns = [
            re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\'"]', re.I),
            re.compile(r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\'"]', re.I),
            re.compile(r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\'"]', re.I),
            re.compile(r'auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\'"]', re.I)
        ]
        
        for pattern in api_key_patterns:
            if pattern.search(html_content):
                vulnerabilities.append({
                    'name': 'Potential API Key/Token Exposure',
                    'description': 'Found what appears to be an API key or token in the page source, which could lead to unauthorized API access.',
                    'severity': 'high',
                    'affected_url': url,
                    'remediation': 'Never include API keys, tokens, or credentials in client-side code. Use server-side API calls instead.'
                })
                break
        
        # Check for possible internal paths or server information
        server_info_patterns = [
            re.compile(r'/(home|var|usr|etc)/[a-zA-Z0-9/._-]+'),
            re.compile(r'[C-Z]:\\[a-zA-Z0-9\\._-]+'),
            re.compile(r'(SQL|MYSQL|POSTGRESQL) error', re.I),
            re.compile(r'stack trace', re.I),
            re.compile(r'(internal server error|500)', re.I)
        ]
        
        for pattern in server_info_patterns:
            if pattern.search(html_content):
                vulnerabilities.append({
                    'name': 'Information Disclosure',
                    'description': 'Found potential server information, file paths, or error messages that could reveal internal system details.',
                    'severity': 'medium',
                    'affected_url': url,
                    'remediation': 'Configure proper error handling to prevent leaking internal information. Use custom error pages in production.'
                })
                break
        
        return vulnerabilities
    
    def check_for_clickjacking(self, headers, url):
        """Check for clickjacking protection."""
        vulnerabilities = []
        
        if 'X-Frame-Options' not in headers:
            vulnerabilities.append({
                'name': 'Clickjacking Vulnerability',
                'description': 'The website does not have X-Frame-Options header set, making it vulnerable to clickjacking attacks.',
                'severity': 'medium',
                'affected_url': url,
                'remediation': 'Add the X-Frame-Options header with a value of "DENY" or "SAMEORIGIN" to prevent your site from being framed.'
            })
        
        return vulnerabilities
    
    def check_for_cors_misconfiguration(self, headers, url):
        """Check for CORS misconfiguration."""
        vulnerabilities = []
        
        if 'Access-Control-Allow-Origin' in headers:
            if headers['Access-Control-Allow-Origin'] == '*':
                vulnerabilities.append({
                    'name': 'CORS Misconfiguration',
                    'description': 'The website has a permissive CORS policy (Access-Control-Allow-Origin: *) which could allow unauthorized websites to access its resources.',
                    'severity': 'medium',
                    'affected_url': url,
                    'remediation': 'Restrict the Access-Control-Allow-Origin header to only trusted domains instead of using the wildcard (*).'
                })
        
        return vulnerabilities
    
    def check_for_server_information(self, headers, url):
        """Check for server information disclosure."""
        vulnerabilities = []
        
        if 'Server' in headers:
            server_info = headers['Server']
            vulnerabilities.append({
                'name': 'Server Information Disclosure',
                'description': f'The server is revealing its identity and possibly version information: {server_info}',
                'severity': 'low',
                'affected_url': url,
                'remediation': 'Configure the web server to suppress the Server header or provide minimal information.'
            })
        
        return vulnerabilities
    
    def check_for_insecure_cookies(self, headers, url):
        """Check for insecure cookie settings."""
        vulnerabilities = []
        
        if 'Set-Cookie' in headers:
            cookies = headers['Set-Cookie'].split(',')
            for cookie in cookies:
                if 'secure' not in cookie.lower() and 'https' in url:
                    vulnerabilities.append({
                        'name': 'Insecure Cookies',
                        'description': 'Cookies are set without the Secure flag, which means they can be transmitted over unencrypted connections.',
                        'severity': 'medium',
                        'affected_url': url,
                        'remediation': 'Set the Secure flag on all cookies that are sent over HTTPS connections.'
                    })
                    break
                
                if 'httponly' not in cookie.lower():
                    vulnerabilities.append({
                        'name': 'HttpOnly Flag Missing',
                        'description': 'Cookies are set without the HttpOnly flag, making them accessible to client-side scripts and vulnerable to XSS attacks.',
                        'severity': 'medium',
                        'affected_url': url,
                        'remediation': 'Set the HttpOnly flag on cookies to prevent access from client-side scripts.'
                    })
                    break
        
        return vulnerabilities
    
    def generate_summary(self, vulnerabilities):
        """Generate a summary of the vulnerabilities found."""
        summary = {
            'total': len(vulnerabilities),
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            if vuln['severity'] == 'high':
                summary['high'] += 1
            elif vuln['severity'] == 'medium':
                summary['medium'] += 1
            elif vuln['severity'] == 'low':
                summary['low'] += 1
            else:
                summary['info'] += 1
        
        return summary
    
    def update_scan_status(self, status=None, progress=None, current_stage=None, vulnerabilities=None, summary=None):
        """Update the scan status in the database."""
        scan_data = {}
        
        if status is not None:
            scan_data['status'] = status
        
        if progress is not None:
            scan_data['progress'] = progress
        
        if current_stage is not None:
            scan_data['current_stage'] = current_stage
        
        if summary is not None:
            scan_data['summary_data'] = summary
        
        # Update the scan with the available data
        if scan_data:
            Scan.objects.filter(id=self.scan_id).update(**scan_data)
        
        # Handle vulnerabilities separately since they're related objects
        if vulnerabilities is not None:
            scan = Scan.objects.get(id=self.scan_id)
            for vuln in vulnerabilities:
                Vulnerability.objects.create(
                    scan=scan,
                    name=vuln['name'],
                    description=vuln['description'],
                    severity=vuln['severity'],
                    affected_url=vuln['affected_url'],
                    remediation=vuln['remediation']
                )