from __future__ import annotations

from datetime import timedelta
from django.utils import timezone
from django.db.models import Count

from celery import shared_task

from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = {"/admin", "/login"}


@shared_task(bind=True, ignore_result=True)
def flag_suspicious_ips(self):
    """
    Task 4: Run hourly (configure in CELERY_BEAT_SCHEDULE).
    Flags:
      - IPs with >100 requests in the last hour
      - IPs that hit sensitive paths in the last hour
    """
    now = timezone.now()
    since = now - timedelta(hours=1)

    # High volume
    high_volume = (
        RequestLog.objects.filter(timestamp__gte=since)
        .values("ip_address")
        .annotate(cnt=Count("id"))
        .filter(cnt__gt=100)
    )

    for row in high_volume:
        ip = row["ip_address"]
        SuspiciousIP.objects.get_or_create(
            ip_address=ip, reason=">100 requests/hour"
        )

    # Sensitive paths
    sensitive = (
        RequestLog.objects.filter(timestamp__gte=since, path__in=SENSITIVE_PATHS)
        .values("ip_address")
        .annotate(cnt=Count("id"))
    )

    for row in sensitive:
        ip = row["ip_address"]
        SuspiciousIP.objects.get_or_create(
            ip_address=ip, reason="Hit sensitive path(s) in last hour"
        )
