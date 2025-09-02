# IP Tracking: Security and Analytics

This project implements a **Django-based IP tracking system** that enhances **security**, provides **analytics**, and ensures **privacy compliance**.

It demonstrates how to log, blacklist, geolocate, rate-limit, and analyze IP addresses in a scalable and ethical way.

---

## 📌 Features

- **Request Logging** – Records IP addresses, request paths, and timestamps.
- **Blacklisting** – Blocks malicious IPs with management command support.
- **Geolocation** – Resolves IPs to **country** and **city** (with caching).
- **Rate Limiting** – Prevents abuse with per-IP limits (different for anonymous vs. authenticated users).
- **Anomaly Detection** – Uses Celery to flag suspicious IPs hitting sensitive endpoints or spamming requests.
- **Privacy & Compliance** – Supports IP anonymization, configurable retention, and GDPR-friendly practices.

---

## ⚙️ Installation

### 1. Clone repository

```bash
git clone https://github.com/kaberege2/alx-backend-security.git
cd alx-backend-security
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt**

```
Django>=5.0
django-ipware>=7.0
django-ratelimit>=4.1
requests>=2.32
celery>=5.3
redis>=5.0
```

### 3. Apply migrations

```bash
python manage.py makemigrations ip_tracking
python manage.py migrate
```
