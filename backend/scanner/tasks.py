import time
import random
from celery import shared_task
from zapv2 import ZAPv2
from .models import Scan, Vulnerability
from .services import ScannerService

@shared_task
def scan_website(scan_id):
    """
    Task to scan a website for vulnerabilities using our enhanced scanner.
    """
    try:
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Initialize scanner with scan_id
        scanner = ScannerService(scan_id)
        
        # Get the URL from the scan object
        url = scan.url
        
        # Perform the scan
        scanner.scan_website(url)
        
        return f"Scan {scan_id} completed"
    except Exception as e:
        # Update scan status to failed if an error occurs
        Scan.objects.filter(id=scan_id).update(
            status="failed",
            progress=0,
            current_stage=f"Error: {str(e)}"
        )
        raise

# Keep the mock_scan_website for testing purposes
@shared_task
def mock_scan_website(scan_id):
    """
    Mock task for development/testing that simulates a website scan.
    """
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'in_progress'
    scan.save()
    
    try:
        stages = [
            "Initializing scanner",
            "Accessing target",
            "Crawling website",
            "Scanning for vulnerabilities",
            "Analyzing results",
            "Completed"
        ]
        
        progress_steps = [5, 10, 30, 70, 90, 100]
        
        for i, (stage, progress) in enumerate(zip(stages, progress_steps)):
            scan.current_stage = stage
            scan.progress = progress
            scan.save()
            
            # Simulate work being done
            time.sleep(random.uniform(1.5, 3.5))
        
        # Create mock vulnerabilities
        vulnerabilities = [
            {
                "name": "Cross-Site Scripting (XSS)",
                "description": "Cross-Site Scripting (XSS) attacks are a type of injection where malicious scripts are injected into trusted websites.",
                "severity": "high",
                "remediation": "Validate and sanitize all user inputs. Use Content Security Policy (CSP) headers."
            },
            {
                "name": "SQL Injection",
                "description": "SQL injection is a code injection technique that might destroy your database.",
                "severity": "high",
                "remediation": "Use parameterized queries or prepared statements. Validate user input and implement least privilege."
            },
            {
                "name": "Cross-Site Request Forgery (CSRF)",
                "description": "CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.",
                "severity": "medium",
                "remediation": "Implement anti-CSRF tokens for all state-changing operations."
            },
            {
                "name": "Insecure Direct Object References",
                "description": "This occurs when an application provides direct access to objects based on user-supplied input.",
                "severity": "medium",
                "remediation": "Implement proper access controls and validate user permissions for each request."
            },
            {
                "name": "Missing HTTP Security Headers",
                "description": "The application is missing important security headers that can help protect against common web vulnerabilities.",
                "severity": "low",
                "remediation": "Implement security headers such as Content-Security-Policy, X-XSS-Protection, X-Content-Type-Options, etc."
            }
        ]
        
        for vuln in vulnerabilities:
            if random.random() > 0.3:  # 70% chance to include each vulnerability
                Vulnerability.objects.create(
                    scan=scan,
                    name=vuln["name"],
                    description=vuln["description"],
                    severity=vuln["severity"],
                    affected_url=scan.url,
                    remediation=vuln["remediation"]
                )
        
        scan.status = 'completed'
        scan.save()
        
        return {"status": "success", "scan_id": scan_id}
        
    except Exception as e:
        scan.status = 'failed'
        scan.save()
        return {"status": "error", "message": str(e)}