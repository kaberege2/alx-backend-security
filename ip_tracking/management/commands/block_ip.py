from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = "Add an IP address to the BlockedIP list."

    def add_arguments(self, parser):
        parser.add_argument("ip_address", type=str, help="IP address to block")
        parser.add_argument(
            "--reason",
            type=str,
            default="manual block",
            help="Reason for blocking (optional)",
        )

    def handle(self, *args, **options):
        ip = options["ip_address"].strip()
        reason = options["reason"]
        try:
            obj, created = BlockedIP.objects.get_or_create(
                ip_address=ip, defaults={"reason": reason}
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Blocked {ip} ({reason})"))
            else:
                self.stdout.write(self.style.WARNING(f"{ip} already blocked"))
        except Exception as exc:
            raise CommandError(str(exc))
