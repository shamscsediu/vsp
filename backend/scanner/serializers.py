from rest_framework import serializers
from .models import Scan, Vulnerability

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = ['id', 'name', 'description', 'severity', 'affected_url', 'remediation']

class ScanSerializer(serializers.ModelSerializer):
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    
    class Meta:
        model = Scan
        fields = ['id', 'url', 'status', 'created_at', 'updated_at', 'progress', 'current_stage', 'vulnerabilities']
        read_only_fields = ['status', 'created_at', 'updated_at', 'progress', 'current_stage', 'vulnerabilities']

class ScanRequestSerializer(serializers.Serializer):
    url = serializers.URLField()