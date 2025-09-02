from __future__ import annotations

from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    path = models.CharField(max_length=512, db_index=True)

    # Task 2: Geolocation fields (nullable)
    country = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    city = models.CharField(max_length=128, null=True, blank=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=["timestamp"]),
            models.Index(fields=["ip_address", "timestamp"]),
            models.Index(fields=["path"]),
        ]

    def __str__(self) -> str:
        return f"{self.ip_address} {self.path} @ {self.timestamp.isoformat()}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"

    def __str__(self) -> str:
        return self.ip_address


class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField(db_index=True)
    reason = models.CharField(max_length=255)
    flagged_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["ip_address", "flagged_at"])]

    def __str__(self) -> str:
        return f"{self.ip_address} - {self.reason}"
