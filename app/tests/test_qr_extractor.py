"""
tests/test_qr_extractor.py
───────────────────────────
Run with:  pytest tests/test_qr_extractor.py -v

Tests:
  1. Valid QR image → correct URL extracted
  2. No QR in image → NoQRFoundError raised
  3. Corrupt bytes → InvalidImageError raised
  4. Multiple QR codes → largest returned
  5. URL without scheme → https:// added
"""

import pytest
import qrcode
import io
import numpy as np
import cv2
from PIL import Image

from app.services.qr_extractor import extract_qr, NoQRFoundError, InvalidImageError


# ══════════════════════════════════════════════════════════════
#  HELPERS — generate test images in memory
# ══════════════════════════════════════════════════════════════

def make_qr_bytes(url: str) -> bytes:
    """Generate a real QR code PNG in memory."""
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def make_blank_image_bytes() -> bytes:
    """Plain white image with no QR code."""
    img = Image.new("RGB", (400, 400), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def make_two_qr_image_bytes(url1: str, url2: str) -> bytes:
    """Image containing two QR codes side by side."""
    qr1 = qrcode.make(url1).resize((200, 200))
    qr2 = qrcode.make(url2).resize((300, 300))   # qr2 is larger

    canvas = Image.new("RGB", (600, 400), "white")
    canvas.paste(qr1, (10, 100))
    canvas.paste(qr2, (250, 50))

    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    return buf.getvalue()


# ══════════════════════════════════════════════════════════════
#  TESTS
# ══════════════════════════════════════════════════════════════

class TestQRExtractor:

    def test_valid_qr_url(self):
        """Standard QR with HTTPS URL — should decode correctly."""
        url   = "https://example.com/test-page"
        img_b = make_qr_bytes(url)
        result = extract_qr(img_b)

        assert result.raw_content == url
        assert result.qr_count == 1
        assert result.bounding_box.w > 0
        assert result.bounding_box.h > 0

    def test_url_without_scheme_gets_normalised(self):
        """QR with bare domain → https:// should be prepended."""
        img_b  = make_qr_bytes("example.com/some/path")
        result = extract_qr(img_b)

        assert result.raw_content.startswith("https://")

    def test_no_qr_raises_error(self):
        """Blank image → NoQRFoundError."""
        img_b = make_blank_image_bytes()
        with pytest.raises(NoQRFoundError):
            extract_qr(img_b)

    def test_corrupt_bytes_raises_error(self):
        """Random bytes that are not an image → InvalidImageError."""
        with pytest.raises(InvalidImageError):
            extract_qr(b"this is not an image at all 12345")

    def test_empty_bytes_raises_error(self):
        """Empty bytes → InvalidImageError."""
        with pytest.raises(InvalidImageError):
            extract_qr(b"")

    def test_multiple_qr_returns_largest(self):
        """Two QRs in one image → largest one returned."""
        url1  = "https://small-qr.com"
        url2  = "https://large-qr.com"
        img_b = make_two_qr_image_bytes(url1, url2)
        result = extract_qr(img_b)

        # Should return url2 because its QR was made larger (300x300 vs 200x200)
        assert result.raw_content == url2
        assert result.qr_count == 2

    def test_bounding_box_fields_present(self):
        """BoundingBox must have x, y, w, h all >= 0."""
        img_b  = make_qr_bytes("https://example.com")
        result = extract_qr(img_b)
        bb     = result.bounding_box

        assert bb.x >= 0
        assert bb.y >= 0
        assert bb.w > 0
        assert bb.h > 0

    def test_non_url_qr_content(self):
        """QR with plain text content — should still decode."""
        img_b  = make_qr_bytes("Hello World — plain text")
        result = extract_qr(img_b)

        assert "Hello World" in result.raw_content
        assert result.qr_count == 1