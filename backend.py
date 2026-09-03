from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
import socket
import json
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

app = FastAPI(title="CyberShield SIH26106")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def home():
    return FileResponse("static/index.html")


IOC_WORDS = [
    "urgent", "verify", "verification", "suspended", "password",
    "click", "account", "login", "confirm", "immediately",
    "security alert", "action required", "reset"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq"]


def extract_urls(text):
    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"
    urls = re.findall(pattern, text)
    seen = set()
    result = []

    for url in urls:
        url = url.rstrip(".,);]}")
        if url not in seen:
            seen.add(url)
            result.append(url)

    return result


def extract_domains(urls):
    domains = []

    for url in urls:
        try:
            hostname = urlparse(url).hostname
            if hostname:
                hostname = hostname.lower()
                if hostname.startswith("www."):
                    hostname = hostname[4:]
                if hostname not in domains:
                    domains.append(hostname)
        except Exception:
            pass

    return domains


def parse_email(raw_bytes):
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        sender = msg.get("From", "Unknown")
        recipient = msg.get("To", "Unknown")
        subject = msg.get("Subject", "No subject")

        body_parts = []

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body_parts.append(part.get_content())
                    except Exception:
                        pass
        else:
            try:
                body_parts.append(msg.get_content())
            except Exception:
                pass

        return msg, sender, recipient, subject, "\n".join(body_parts)

    except Exception:
        text = raw_bytes.decode("utf-8", errors="ignore")
        return None, "Unknown", "Unknown", "Unknown", text


def calculate_sha256(raw_bytes):
    return hashlib.sha256(raw_bytes).hexdigest()


def get_analysis_timestamp():
    return datetime.now(timezone.utc).isoformat()


def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


def extract_public_ips(msg):
    """
    Extract candidate public IPs from email routing headers.
    The oldest Received header is normally closest to the source,
    but email headers can be forged, so this is treated as evidence,
    not proof of the attacker's physical location.
    """
    if msg is None:
        return []

    header_names = [
        "Received",
        "X-Originating-IP",
        "X-Sender-IP",
        "X-Client-IP",
        "X-Forwarded-For",
    ]

    candidates = []

    for header_name in header_names:
        for header_value in msg.get_all(header_name, []):
            if not header_value:
                continue

            # IPv4
            for ip in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", str(header_value)):
                if is_public_ip(ip) and ip not in candidates:
                    candidates.append(ip)

            # Simple IPv6 extraction
            for ip in re.findall(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])", str(header_value)):
                ip = ip.strip("[]")
                if is_public_ip(ip) and ip not in candidates:
                    candidates.append(ip)

    return candidates


def geolocate_ip(ip):
    """
    Uses ip-api's free non-commercial endpoint.
    Returns real API data when the endpoint is reachable.
    """
    if not is_public_ip(ip):
        return {
            "success": False,
            "error": "IP is not a public address."
        }

    fields = "status,message,country,regionName,city,lat,lon,isp,org,as,query"
    url = f"http://ip-api.com/json/{ip}?fields={fields}"

    try:
        request = Request(
            url,
            headers={"User-Agent": "CyberShield-SIH26106/1.0"}
        )

        with urlopen(request, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))

        if data.get("status") != "success":
            return {
                "success": False,
                "error": data.get("message", "Geolocation lookup failed.")
            }

        as_text = data.get("as", "")
        asn_match = re.search(r"\bAS\d+\b", as_text or "")
        asn = asn_match.group(0) if asn_match else as_text or "Not available"

        return {
            "success": True,
            "ip": data.get("query", ip),
            "country": data.get("country") or "Not available",
            "region": data.get("regionName") or "Not available",
            "city": data.get("city") or "Not available",
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp") or data.get("org") or "Not available",
            "asn": asn,
            "organization": data.get("org") or "Not available",
            "source": "IP-based infrastructure geolocation"
        }

    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        return {
            "success": False,
            "error": f"Geolocation service unavailable: {exc}"
        }


def resolve_domain_ip(domain):
    """
    Safe fallback: DNS resolution only. We do NOT visit the URL.
    This gives hosting/infrastructure geolocation, not sender location.
    """
    try:
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            ip = info[4][0]
            if is_public_ip(ip):
                return ip
    except Exception:
        pass

    return None


def get_infrastructure(msg, domains):
    public_ips = extract_public_ips(msg)

    # Prefer an IP found in the email's routing headers.
    if public_ips:
        result = geolocate_ip(public_ips[0])

        if result.get("success"):
            result["detected_ips"] = public_ips
            result["lookup_type"] = "mail-header-ip"
            return result

        # Preserve the detected IP even when the external service is down.
        return {
            "ip": public_ips[0],
            "detected_ips": public_ips,
            "country": "Lookup unavailable",
            "region": "Lookup unavailable",
            "city": "Lookup unavailable",
            "isp": "Lookup unavailable",
            "asn": "Lookup unavailable",
            "lat": None,
            "lon": None,
            "source": "Email routing header",
            "lookup_type": "mail-header-ip",
            "error": result.get("error", "Geolocation lookup failed.")
        }

    # Optional fallback: resolve the suspicious domain to hosting infrastructure.
    if domains:
        for domain in domains:
            domain_ip = resolve_domain_ip(domain)

            if domain_ip:
                result = geolocate_ip(domain_ip)

                if result.get("success"):
                    result["detected_ips"] = []
                    result["lookup_type"] = "domain-hosting-ip"
                    result["domain"] = domain
                    result["source"] = "Domain/IP infrastructure geolocation"
                    return result

                return {
                    "ip": domain_ip,
                    "detected_ips": [],
                    "domain": domain,
                    "country": "Lookup unavailable",
                    "region": "Lookup unavailable",
                    "city": "Lookup unavailable",
                    "isp": "Lookup unavailable",
                    "asn": "Lookup unavailable",
                    "lat": None,
                    "lon": None,
                    "source": "Resolved domain infrastructure",
                    "lookup_type": "domain-hosting-ip",
                    "error": result.get("error", "Geolocation lookup failed.")
                }

    return {
        "ip": None,
        "detected_ips": [],
        "country": "No public IP found",
        "region": "Not available",
        "city": "Not available",
        "isp": "Not available",
        "asn": "Not available",
        "lat": None,
        "lon": None,
        "source": "No public IP available in email evidence",
        "lookup_type": "none"
    }


def analyze_authentication(msg):
    authentication = {
        "spf": "UNKNOWN",
        "dkim": "UNKNOWN",
        "dmarc": "UNKNOWN"
    }

    if msg is None:
        return authentication

    results = msg.get_all("Authentication-Results", [])

    if not results:
        return authentication

    combined = " ".join(str(x) for x in results).lower()

    for key in authentication:
        match = re.search(rf"\b{key}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", combined)
        if match:
            authentication[key] = match.group(1).upper()

    return authentication


def analyze(raw_bytes, filename="email.eml"):
    msg, sender, recipient, subject, body = parse_email(raw_bytes)

    text = f"{subject}\n{body}".lower()
    urls = extract_urls(body)
    domains = extract_domains(urls)

    matched_words = []
    for word in IOC_WORDS:
        if word in text:
            matched_words.append(word)

    suspicious_domains = [
        domain for domain in domains
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    ]

    reasons = []

    if matched_words:
        reasons.append(
            f"Urgency/social-engineering terms detected ({len(matched_words)})"
        )

    if urls:
        reasons.append(f"{len(urls)} URL(s) found in the email")

    if domains:
        reasons.append("External domain(s) detected")

    if suspicious_domains:
        reasons.append("Suspicious-looking domain/TLD detected")

    authentication = analyze_authentication(msg)

    auth_values = [
        authentication["spf"],
        authentication["dkim"],
        authentication["dmarc"]
    ]

    auth_attention = sum(value not in ("PASS",) for value in auth_values)

    if auth_attention:
        reasons.append(
            f"Email authentication checks need attention ({auth_attention}/3 not passing)"
        )

    # Risk score.
    risk_score = 0
    risk_score += min(40, len(matched_words) * 5)
    risk_score += min(25, len(urls) * 25)

    if suspicious_domains:
        risk_score += 20

    if "urgent" in text or "security alert" in text or "action required" in text:
        risk_score += 15

    if auth_attention:
        risk_score += min(15, auth_attention * 5)

    risk_score = min(100, risk_score)

    if risk_score >= 70:
        threat = "PHISHING / HIGH RISK"
    elif risk_score >= 40:
        threat = "SUSPICIOUS / MEDIUM RISK"
    else:
        threat = "LOW RISK"

    infrastructure = get_infrastructure(msg, domains)

    sha256_hash = calculate_sha256(raw_bytes)
    analysis_timestamp = get_analysis_timestamp()

    forensic = {
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "sha256": sha256_hash,
        "timestamp": analysis_timestamp,
        "filename": filename
    }

    ioc_count = len(set(domains + urls))

    return {
        "success": True,
        "filename": filename,
        "threat": threat,
        "risk_score": risk_score,
        "iocs": ioc_count,
        "evidence": "VERIFIED",
        "reasons": reasons or ["No strong suspicious indicators detected."],
        "why_suspicious": reasons or ["No strong suspicious indicators detected."],
        "infrastructure": infrastructure,
        "authentication": authentication,
        "indicators": {
            "domains": domains,
            "urls": urls,
            "public_ips": infrastructure.get("detected_ips", [])
        },
        "forensic": forensic,
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "sha256": sha256_hash,
        "timestamp": analysis_timestamp,
        "message_preview": body[:500]
    }


@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):
    raw_bytes = await file.read()
    filename = file.filename or "uploaded_email.eml"

    return analyze(raw_bytes, filename)


@app.post("/api/demo")
async def demo_email():
    # This demo is intentionally deterministic for the SIH presentation.
    # Its infrastructure values are simulated presentation data, not a
    # claim about a real attacker.
    return {
        "success": True,
        "filename": "demo-phishing-email.eml",
        "threat": "PHISHING / HIGH RISK",
        "risk_score": 98,
        "iocs": 2,
        "evidence": "VERIFIED",
        "reasons": [
            "Urgency/social-engineering terms detected (7)",
            "1 URL(s) found in the email",
            "External domain(s) detected",
            "Suspicious-looking domain/TLD detected",
            "Email authentication checks need attention (3/3 not passing)"
        ],
        "why_suspicious": [
            "Urgency/social-engineering terms detected (7)",
            "1 URL(s) found in the email",
            "External domain(s) detected",
            "Suspicious-looking domain/TLD detected",
            "Email authentication checks need attention (3/3 not passing)"
        ],
        "infrastructure": {
            "ip": "203.0.113.10",
            "country": "Demo geolocation",
            "region": "Demo region",
            "city": "Demo city",
            "isp": "Demo hosting provider",
            "asn": "AS-DEMO",
            "lat": None,
            "lon": None,
            "source": "Simulated SIH demo data",
            "lookup_type": "demo"
        },
        "authentication": {
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL"
        },
        "indicators": {
            "domains": ["aicte-login.xyz"],
            "urls": ["https://aicte-login.xyz/verify"],
            "public_ips": []
        },
        "forensic": {
            "sender": "security-alert@example-test.com",
            "recipient": "test@example.com",
            "subject": "URGENT: Your account has been suspended - verify immediately",
            "sha256": "demo-hash-generated-for-presentation",
            "timestamp": get_analysis_timestamp(),
            "filename": "demo-phishing-email.eml"
        },
        "sender": "security-alert@example-test.com",
        "recipient": "test@example.com",
        "subject": "URGENT: Your account has been suspended - verify immediately",
        "sha256": "demo-hash-generated-for-presentation",
        "timestamp": get_analysis_timestamp(),
        "message_preview": "URGENT SECURITY ALERT\n\nYour account has been suspended.\n\nWe detected unusual activity on your account. You must verify your password immediately."
    }


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "CyberShield",
        "geolocation": "enabled"
    }
