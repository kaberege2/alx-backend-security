from __future__ import annotations

from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST

from django_ratelimit.core import is_ratelimited


def _apply_ip_rate_limit(request) -> None | HttpResponse:
    """
    Task 3: Rate limiting by IP with different limits for auth vs anon.
    Uses django-ratelimit's core API for dynamic rates.
    """
    rate = "10/m" if request.user.is_authenticated else "5/m"
    blocked = is_ratelimited(
        request=request,
        group="ip_tracking.login",
        key="ip",           # use client's IP
        rate=rate,
        method=["POST"],    # apply to POST only (typical for login)
        increment=True,     # count this request
    )
    if blocked:
        return HttpResponse("Too Many Requests", status=429)
    return None


@require_POST
def login_view(request):
    """
    Dummy sensitive view to demonstrate rate limiting.
    Replace with your actual login logic (e.g., django.contrib.auth views).
    """
    # Enforce dynamic rate limit by IP:
    limited = _apply_ip_rate_limit(request)
    if limited:
        return limited

    # Your real login logic would go here; we just echo ok for demo
    return JsonResponse({"ok": True, "message": "Login attempt recorded"})
