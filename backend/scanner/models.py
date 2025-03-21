from django.db import models
import json

class Scan(models.Model):
    url = models.URLField()
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed')
    ], default='pending')
    progress = models.IntegerField(default=0)
    current_stage = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # Add a JSON field for summary data
    summary_data = models.JSONField(blank=True, null=True)
    
    def __str__(self):
        return f"Scan of {self.url} ({self.status})"
    
    @property
    def summary(self):
        return self.summary_data
    
    @summary.setter
    def summary(self, value):
        self.summary_data = value

class Vulnerability(models.Model):
    SEVERITY_CHOICES = (
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    )
    
    scan = models.ForeignKey(Scan, related_name='vulnerabilities', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    affected_url = models.URLField()
    remediation = models.TextField()
    
    def __str__(self):
        return f"{self.name} ({self.severity}) on {self.scan.url}"
