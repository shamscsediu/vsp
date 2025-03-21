from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Scan
from .serializers import ScanSerializer, ScanRequestSerializer
from .tasks import scan_website  # Changed from mock_scan_website to real scanner
from .services import ScannerService

class StartScanView(APIView):
    def post(self, request):
        serializer = ScanRequestSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            scan = Scan.objects.create(url=url, status='pending')
            
            # Use the real scanner instead of mock_scan_website
            scan_website.delay(scan.id)
            
            return Response({
                'scan_id': scan.id,
                'status': 'pending'
            }, status=status.HTTP_202_ACCEPTED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ScanStatusView(APIView):
    def get(self, request, scan_id):
        try:
            scan = Scan.objects.get(id=scan_id)
            serializer = ScanSerializer(scan)
            
            # Calculate summary counts for completed scans
            if scan.status == 'completed':
                vulnerabilities = scan.vulnerabilities.all()
                summary = {
                    'total': vulnerabilities.count(),
                    'high': vulnerabilities.filter(severity='high').count(),
                    'medium': vulnerabilities.filter(severity='medium').count(),
                    'low': vulnerabilities.filter(severity='low').count(),
                    'info': vulnerabilities.filter(severity='info').count(),
                }
                data = serializer.data
                data['summary'] = summary
                return Response(data)
            
            return Response(serializer.data)
        except Scan.DoesNotExist:
            return Response(
                {'error': 'Scan not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

# Add a new view for detailed vulnerability information
class VulnerabilityDetailView(APIView):
    def get(self, request, scan_id, vuln_id):
        try:
            scan = Scan.objects.get(id=scan_id)
            vulnerability = scan.vulnerabilities.get(id=vuln_id)
            
            # Return detailed information about the vulnerability
            return Response({
                'id': vulnerability.id,
                'name': vulnerability.name,
                'description': vulnerability.description,
                'severity': vulnerability.severity,
                'affected_url': vulnerability.affected_url,
                'remediation': vulnerability.remediation,
                'details': vulnerability.details if hasattr(vulnerability, 'details') else None,
                'discovered_at': vulnerability.created_at
            })
        except (Scan.DoesNotExist, vulnerability.DoesNotExist):
            return Response(
                {'error': 'Vulnerability or scan not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

# Add a new view for rescanning a website
class RescanView(APIView):
    def post(self, request, scan_id):
        try:
            original_scan = Scan.objects.get(id=scan_id)
            
            # Create a new scan for the same URL
            new_scan = Scan.objects.create(
                url=original_scan.url,
                status='pending'
            )
            
            # Start the scan process
            scan_website.delay(new_scan.id)
            
            return Response({
                'scan_id': new_scan.id,
                'status': 'pending',
                'message': f'Rescan of {original_scan.url} initiated'
            }, status=status.HTTP_202_ACCEPTED)
        except Scan.DoesNotExist:
            return Response(
                {'error': 'Original scan not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

# Add a new view for comparing scan results
class CompareScanView(APIView):
    def get(self, request, scan_id1, scan_id2):
        try:
            scan1 = Scan.objects.get(id=scan_id1)
            scan2 = Scan.objects.get(id=scan_id2)
            
            # Ensure both scans are completed
            if scan1.status != 'completed' or scan2.status != 'completed':
                return Response(
                    {'error': 'Both scans must be completed to compare'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get vulnerabilities from both scans
            vulns1 = scan1.vulnerabilities.all()
            vulns2 = scan2.vulnerabilities.all()
            
            # Create summary counts
            summary1 = {
                'total': vulns1.count(),
                'high': vulns1.filter(severity='high').count(),
                'medium': vulns1.filter(severity='medium').count(),
                'low': vulns1.filter(severity='low').count(),
                'info': vulns1.filter(severity='info').count(),
            }
            
            summary2 = {
                'total': vulns2.count(),
                'high': vulns2.filter(severity='high').count(),
                'medium': vulns2.filter(severity='medium').count(),
                'low': vulns2.filter(severity='low').count(),
                'info': vulns2.filter(severity='info').count(),
            }
            
            # Find new and fixed vulnerabilities
            vuln_names1 = {v.name + v.affected_url for v in vulns1}
            vuln_names2 = {v.name + v.affected_url for v in vulns2}
            
            new_vulns = vuln_names2 - vuln_names1
            fixed_vulns = vuln_names1 - vuln_names2
            
            return Response({
                'scan1': {
                    'id': scan1.id,
                    'url': scan1.url,
                    'date': scan1.created_at,
                    'summary': summary1
                },
                'scan2': {
                    'id': scan2.id,
                    'url': scan2.url,
                    'date': scan2.created_at,
                    'summary': summary2
                },
                'comparison': {
                    'new_vulnerabilities_count': len(new_vulns),
                    'fixed_vulnerabilities_count': len(fixed_vulns)
                }
            })
        except Scan.DoesNotExist:
            return Response(
                {'error': 'One or both scans not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
