from django.urls import path
from .views import StartScanView, ScanStatusView, VulnerabilityDetailView, RescanView, CompareScanView

urlpatterns = [
    path('start-scan/', StartScanView.as_view(), name='start-scan'),
    path('scan-status/<int:scan_id>/', ScanStatusView.as_view(), name='scan-status'),
    path('vulnerability/<int:scan_id>/<int:vuln_id>/', VulnerabilityDetailView.as_view(), name='vulnerability-detail'),
    path('rescan/<int:scan_id>/', RescanView.as_view(), name='rescan'),
    path('compare/<int:scan_id1>/<int:scan_id2>/', CompareScanView.as_view(), name='compare-scans'),
]