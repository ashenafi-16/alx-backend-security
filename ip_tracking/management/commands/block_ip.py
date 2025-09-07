from django.core.management.base import BaseCommand
from django.core.management import CommandError
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Add IP addresses to the blocked list'

    def add_arguments(self, parser):
        parser.add_argument(
            'ip_addresses',
            nargs='+',
            type=str,
            help='IP addresses to block'
        )

    def handle(self, *args, **options):
        ip_addresses = options['ip_addresses']
        
        for ip_address in ip_addresses:
            try:
                blocked_ip, created = BlockedIP.objects.get_or_create(
                    ip_address=ip_address
                )
                
                if created:
                    self.stdout.write(
                        self.style.SUCCESS(f'Successfully blocked IP: {ip_address}')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'IP already blocked: {ip_address}')
                    )
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error blocking IP {ip_address}: {e}')
                )