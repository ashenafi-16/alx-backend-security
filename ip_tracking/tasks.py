from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP

@shared_task
def detect_suspicious_ips():
    """
    Hourly task to detect suspicious IP activity
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    # Detect IPs with excessive requests (>100/hour)
    excessive_requests = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=100)
    
    for item in excessive_requests:
        ip_address = item['ip_address']
        count = item['request_count']
        
        SuspiciousIP.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'reason': f'Excessive requests: {count} requests in the last hour',
                'is_active': True
            }
        )
    
    # Detect IPs accessing sensitive paths
    sensitive_paths = ['/admin/', '/login/', '/api/auth/', '/password-reset/']
    
    sensitive_access = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=sensitive_paths
    ).values('ip_address').annotate(
        access_count=Count('id')
    ).filter(access_count__gt=5)  # More than 5 accesses to sensitive paths
    
    for item in sensitive_access:
        ip_address = item['ip_address']
        count = item['access_count']
        
        SuspiciousIP.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'reason': f'Multiple accesses to sensitive paths: {count} accesses in the last hour',
                'is_active': True
            }
        )
    
    return f"Detected {len(excessive_requests)} excessive request IPs and {len(sensitive_access)} sensitive path access IPs"