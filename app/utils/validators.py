"""
app/utils/validators.py
────────────────────────
Input validation helpers used across the app.
All validation logic lives here — never inline.
"""

import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger("safeqr.validators")


# ══════════════════════════════════════════════════════════════
#  URL VALIDATORS
# ══════════════════════════════════════════════════════════════

def is_valid_url(url: str) -> bool:
    """
    Return True if string is a well-formed HTTP/HTTPS URL.
    Does NOT check if the URL is reachable.
    """
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def is_url_like(raw: str) -> bool:
    """
    Looser check — catches URLs without scheme (e.g. 'example.com/path').
    Used when QR content might be a URL without http://.
    """
    pattern = re.compile(
        r"(https?://)?"                    # optional scheme
        r"([\w\-]+\.)+[\w\-]{2,}"          # domain
        r"(/[\w\-._~:/?#\[\]@!$&\'()*+,;=%]*)?"  # optional path
    )
    return bool(pattern.match(raw.strip()))


def normalise_url(raw: str) -> str:
    """
    Add https:// if no scheme present.
    'example.com' → 'https://example.com'
    """
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


# ══════════════════════════════════════════════════════════════
#  QR CONTENT TYPE DETECTION
# ══════════════════════════════════════════════════════════════

def classify_qr_content(raw: str) -> str:
    """
    Classify what type of content the QR code contains.
    Returns one of: URL, EMAIL, PHONE, SMS, WIFI, TEXT
    """
    raw = raw.strip()

    if raw.startswith(("http://", "https://")):
        return "URL"
    if raw.startswith("mailto:"):
        return "EMAIL"
    if raw.startswith("tel:"):
        return "PHONE"
    if raw.startswith("sms:"):
        return "SMS"
    if raw.upper().startswith("WIFI:"):
        return "WIFI"
    if is_url_like(raw):
        return "URL"         # treat domain-only as URL

    return "TEXT"


# ══════════════════════════════════════════════════════════════
#  FILE VALIDATORS
# ══════════════════════════════════════════════════════════════

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}

def validate_filename(filename: str) -> None:
    """Raise ValueError if file extension is not allowed."""
    import os
    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"File type '{ext}' not supported. "
            f"Use: {', '.join(ALLOWED_EXTENSIONS)}"
        )