"""
app/services/qr_extractor.py
─────────────────────────────
QR Extraction Engine.

Input  : raw image bytes
Output : QRResult (raw_content, bounding_box, qr_count)

Strategy:
  1. Try pyzbar on original image          (fastest)
  2. Try pyzbar on preprocessed variants   (handles bad lighting)
  3. Try OpenCV QRCodeDetector fallback    (handles rotated/small QR)
  4. If still nothing → raise NoQRFound

Handles:
  - No QR found
  - Multiple QRs (returns the largest/most central one)
  - Corrupt / non-image bytes
  - QR with non-URL content (WiFi, email, plain text)
"""

import cv2
import numpy as np
import logging
from pyzbar.pyzbar import decode as pyzbar_decode, ZBarSymbol
from PIL import Image

from app.models.response_models import QRResult, BoundingBox
from app.utils.image_utils import (
    bytes_to_cv2,
    bytes_to_pil,
    preprocess_for_qr,
)
from app.utils.validators import classify_qr_content, normalise_url

logger = logging.getLogger("safeqr.qr_extractor")


# ══════════════════════════════════════════════════════════════
#  CUSTOM EXCEPTIONS
# ══════════════════════════════════════════════════════════════

class NoQRFoundError(Exception):
    """Raised when no QR code is detected in the image."""
    pass


class InvalidImageError(Exception):
    """Raised when the image cannot be decoded at all."""
    pass


# ══════════════════════════════════════════════════════════════
#  INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════

def _pyzbar_on_pil(pil_img: Image.Image) -> list[dict]:
    """
    Run pyzbar on a PIL image.
    Returns list of dicts with keys: data, rect
    """
    results = []
    decoded = pyzbar_decode(pil_img, symbols=[ZBarSymbol.QRCODE])
    for d in decoded:
        rect = d.rect          # pyzbar Rect: left, top, width, height
        results.append({
            "data": d.data.decode("utf-8", errors="replace"),
            "x": rect.left,
            "y": rect.top,
            "w": rect.width,
            "h": rect.height,
        })
    return results


def _pyzbar_on_cv2(cv_img: np.ndarray) -> list[dict]:
    """
    Run pyzbar on an OpenCV array.
    Converts to PIL first internally.
    """
    # Convert BGR → RGB for PIL
    if len(cv_img.shape) == 2:
        # grayscale — PIL can handle this directly
        pil = Image.fromarray(cv_img)
    else:
        pil = Image.fromarray(cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB))
    return _pyzbar_on_pil(pil)


def _opencv_detector(cv_img: np.ndarray) -> list[dict]:
    """
    OpenCV QRCodeDetector fallback.
    Better at rotated or low-contrast QR codes.
    Returns list of dicts same format as pyzbar helpers.
    """
    results   = []
    detector  = cv2.QRCodeDetector()

    # detectAndDecodeMulti handles multiple QRs
    try:
        ok, decoded_list, points_list, _ = detector.detectAndDecodeMulti(cv_img)
        if ok and decoded_list:
            for i, data in enumerate(decoded_list):
                if not data:
                    continue
                if points_list is not None and i < len(points_list):
                    pts = points_list[i].astype(int)
                    x   = int(pts[:, 0].min())
                    y   = int(pts[:, 1].min())
                    w   = int(pts[:, 0].max()) - x
                    h   = int(pts[:, 1].max()) - y
                else:
                    x, y, w, h = 0, 0, 100, 100
                results.append({"data": data, "x": x, "y": y, "w": w, "h": h})
    except Exception as e:
        logger.debug(f"OpenCV QRCodeDetector error: {e}")

    return results


def _pick_best_qr(candidates: list[dict]) -> dict:
    """
    If multiple QR codes found, pick the best one.
    Strategy: largest area (most likely the intentional QR).
    """
    return max(candidates, key=lambda c: c["w"] * c["h"])


# ══════════════════════════════════════════════════════════════
#  MAIN EXTRACT FUNCTION
# ══════════════════════════════════════════════════════════════

def extract_qr(img_bytes: bytes) -> QRResult:
    """
    Main entry point for QR extraction.

    Args:
        img_bytes: Raw bytes of the uploaded image

    Returns:
        QRResult with raw_content, bounding_box, qr_count

    Raises:
        InvalidImageError: if bytes cannot be decoded as an image
        NoQRFoundError: if no QR code is found after all attempts
    """

    # ── Step 1: Load image ────────────────────────────────────
    try:
        cv_img  = bytes_to_cv2(img_bytes)
        pil_img = bytes_to_pil(img_bytes)
    except ValueError as e:
        raise InvalidImageError(str(e))

    logger.info(f"Image loaded: {cv_img.shape[1]}x{cv_img.shape[0]}px")

    # ── Step 2: Try pyzbar on original PIL image ──────────────
    candidates = _pyzbar_on_pil(pil_img)

    if candidates:
        logger.info(f"pyzbar found {len(candidates)} QR(s) on original image")

    # ── Step 3: Try preprocessed variants if nothing found ────
    if not candidates:
        logger.debug("pyzbar found nothing on original — trying preprocessed variants")
        variants = preprocess_for_qr(cv_img)

        for i, variant in enumerate(variants[1:], start=1):   # skip original
            result = _pyzbar_on_cv2(variant)
            if result:
                logger.info(f"pyzbar found QR on variant #{i}")
                candidates = result
                break

    # ── Step 4: OpenCV fallback ───────────────────────────────
    if not candidates:
        logger.debug("pyzbar failed all variants — trying OpenCV QRCodeDetector")
        candidates = _opencv_detector(cv_img)
        if candidates:
            logger.info(f"OpenCV detector found {len(candidates)} QR(s)")

    # ── Step 5: Nothing found ─────────────────────────────────
    if not candidates:
        raise NoQRFoundError(
            "No QR code detected. Ensure the QR code is clearly visible, "
            "well-lit, and not blurry."
        )

    # ── Step 6: Pick best + build result ─────────────────────
    qr_count = len(candidates)
    best     = _pick_best_qr(candidates)
    raw      = best["data"].strip()

    # Normalise URL if needed
    content_type = classify_qr_content(raw)
    if content_type == "URL":
        raw = normalise_url(raw)

    logger.info(f"QR decoded: type={content_type} content={raw[:80]}")

    return QRResult(
        raw_content  = raw,
        bounding_box = BoundingBox(
            x = best["x"],
            y = best["y"],
            w = best["w"],
            h = best["h"],
        ),
        qr_count = qr_count,
    )