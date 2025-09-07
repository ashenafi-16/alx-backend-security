import logging
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils import timezone
from .models import RequestLog, BlockedIP
from ipgeolocation import IpGeolocationAPI
from django.conf import settings

logger = logging.getLogger(__name__)

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # Initialize geolocation API if key is available
        self.geolocation_api = None
        if hasattr(settings, 'IPGEOLOCATION_API_KEY') and settings.IPGEOLOCATION_API_KEY:
            self.geolocation_api = IpGeolocationAPI(settings.IPGEOLOCATION_API_KEY)

    def __call__(self, request):
        # Get client IP address
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            return HttpResponseForbidden("Access denied: IP address blocked")
        
        # Process the request
        response = self.get_response(request)
        
        # Log the request after processing
        self.log_request(request, ip_address)
        
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def is_ip_blocked(self, ip_address):
        return BlockedIP.objects.filter(ip_address=ip_address).exists()

    def get_geolocation_data(self, ip_address):
        """Get geolocation data with caching"""
        cache_key = f'geolocation_{ip_address}'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return cached_data
        
        if not self.geolocation_api:
            return {'country': None, 'city': None}
        
        try:
            # Get geolocation data
            geolocation_data = self.geolocation_api.get_geolocation(ip_address)
            
            if geolocation_data and not geolocation_data.get('error'):
                data = {
                    'country': geolocation_data.get('country_name'),
                    'city': geolocation_data.get('city')
                }
                # Cache for 24 hours
                cache.set(cache_key, data, 60 * 60 * 24)
                return data
        except Exception as e:
            logger.error(f"Geolocation API error for IP {ip_address}: {e}")
        
        return {'country': None, 'city': None}

    def log_request(self, request, ip_address):
        """Log the request with geolocation data"""
        try:
            # Get geolocation data
            geolocation_data = self.get_geolocation_data(ip_address)
            
            # Create request log entry
            RequestLog.objects.create(
                ip_address=ip_address,
                path=request.path,
                country=geolocation_data['country'],
                city=geolocation_data['city']
            )
            
        except Exception as e:
            logger.error(f"Error logging request: {e}")