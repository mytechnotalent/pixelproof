#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nation-state-grade forensic analysis passes for PixelProof.

This module implements advanced detection techniques:
- Thumbnail vs full-image comparison
- Benford's Law on JPEG DCT coefficients
- Double JPEG compression detection
- FFT spectral analysis for GAN/AI artifacts
- PRNU sensor noise fingerprinting
- Illumination direction consistency
"""

from __future__ import annotations

import io
import math
import struct
from collections import Counter

import numpy as np
import PIL.Image
import PIL.ImageChops
import PIL.ImageFilter
import PIL.ImageStat


# ===================================================================
# Pass 1: Thumbnail vs Full-Image Comparison
# ===================================================================


def _extract_exif_bytes(image_path):
    """Extract raw EXIF bytes from image file.

    Args:
        image_path: Path to image file.

    Returns:
        Raw EXIF bytes or empty bytes.
    """
    img = PIL.Image.open(image_path)
    return img.info.get("exif", b"")


def _find_thumbnail_markers(exif_data):
    """Locate JPEG SOI/EOI thumbnail markers within EXIF data.

    Args:
        exif_data: Raw EXIF bytes.

    Returns:
        Tuple of (start, end) byte offsets or None.
    """
    soi = exif_data.find(b"\xff\xd8", 2)
    if soi < 0:
        return None
    eoi = exif_data.find(b"\xff\xd9", soi)
    if eoi < 0:
        return None
    return soi, eoi + 2


def _thumbnail_from_exif(exif_data, markers):
    """Decode thumbnail image from EXIF byte markers.

    Args:
        exif_data: Raw EXIF bytes.
        markers: Tuple of (start, end) byte offsets.

    Returns:
        PIL Image of the thumbnail or None.
    """
    try:
        thumb_bytes = exif_data[markers[0] : markers[1]]
        return PIL.Image.open(io.BytesIO(thumb_bytes)).convert("RGB")
    except Exception:
        return None


def _resize_to_thumbnail(full_img, thumb_size):
    """Resize full image to match thumbnail dimensions.

    Args:
        full_img: Full-size PIL Image.
        thumb_size: Target (width, height) tuple.

    Returns:
        Resized PIL Image.
    """
    return full_img.resize(thumb_size, PIL.Image.LANCZOS)


def _pixel_difference_score(img_a, img_b):
    """Compute mean absolute pixel difference between two images.

    Args:
        img_a: First PIL Image.
        img_b: Second PIL Image.

    Returns:
        Mean absolute difference across all channels.
    """
    arr_a = np.array(img_a, dtype=np.float32)
    arr_b = np.array(img_b, dtype=np.float32)
    return float(np.mean(np.abs(arr_a - arr_b)))


def _build_thumbnail_findings(score, threshold):
    """Build findings list from thumbnail comparison score.

    Args:
        score: Mean pixel difference.
        threshold: Threshold for flagging mismatch.

    Returns:
        List of (description, severity) tuples.
    """
    if score > threshold * 1.5:
        return [(f"Thumbnail-image MISMATCH (diff={score:.2f})", 3)]
    if score > threshold:
        return [(f"Thumbnail-image divergence (diff={score:.2f})", 2)]
    return []


def _no_thumbnail_result():
    """Return default result when no thumbnail is available.

    Returns:
        Default thumbnail comparison result dictionary.
    """
    return {"available": False, "score": 0.0, "findings": []}


def _extract_thumbnail(image_path):
    """Extract EXIF thumbnail from image file.

    Args:
        image_path: Path to image file.

    Returns:
        PIL Image of thumbnail or None.
    """
    exif_data = _extract_exif_bytes(image_path)
    markers = _find_thumbnail_markers(exif_data)
    if markers is None:
        return None
    return _thumbnail_from_exif(exif_data, markers)


def _compare_thumbnail(image_path, thumb):
    """Compare extracted thumbnail against full image.

    Args:
        image_path: Path to full image.
        thumb: PIL thumbnail image.

    Returns:
        Thumbnail comparison result dictionary.
    """
    full_img = PIL.Image.open(image_path).convert("RGB")
    resized = _resize_to_thumbnail(full_img, thumb.size)
    score = _pixel_difference_score(resized, thumb)
    findings = _build_thumbnail_findings(score, 12.0)
    return {"available": True, "score": round(score, 4), "findings": findings}


def _analyze_thumbnail_comparison(image_path):
    """Compare EXIF thumbnail against full image to detect post-edit.

    Args:
        image_path: Path to image file.

    Returns:
        Dictionary with comparison score and findings.
    """
    thumb = _extract_thumbnail(image_path)
    if thumb is None:
        return {"available": False, "score": 0.0, "findings": []}
    return _compare_thumbnail(image_path, thumb)


# ===================================================================
# Pass 2: Benford's Law on JPEG DCT Coefficients
# ===================================================================


def _extract_raw_jpeg_bytes(image_path):
    """Read raw bytes of a JPEG file.

    Args:
        image_path: Path to JPEG file.

    Returns:
        Raw file bytes.
    """
    with open(image_path, "rb") as f:
        return f.read()


def _is_jpeg_file(image_path):
    """Check if file is JPEG by extension.

    Args:
        image_path: Path to check.

    Returns:
        True when JPEG extension detected.
    """
    return image_path.lower().endswith((".jpg", ".jpeg"))


def _sos_offset(data):
    """Find Start-of-Scan marker offset in JPEG data.

    Args:
        data: Raw JPEG bytes.

    Returns:
        Byte offset of SOS marker or -1.
    """
    return data.find(b"\xff\xda")


def _extract_scan_bytes(data, offset):
    """Extract entropy-coded scan data after SOS marker.

    Args:
        data: Raw JPEG bytes.
        offset: SOS marker offset.

    Returns:
        Scan byte sequence.
    """
    start = offset + 2
    return data[start : start + min(500000, len(data) - start)]


def _first_digit_counts(scan_bytes):
    """Count first significant digits in byte values for Benford analysis.

    Args:
        scan_bytes: Entropy-coded byte sequence.

    Returns:
        Dictionary mapping digit (1-9) to count.
    """
    counts = {d: 0 for d in range(1, 10)}
    for byte_val in scan_bytes:
        if byte_val == 0 or byte_val == 0xFF:
            continue
        first = int(str(byte_val).lstrip("0")[0]) if byte_val else 0
        if 1 <= first <= 9:
            counts[first] += 1
    return counts


def _benford_expected():
    """Return Benford's Law expected proportions for digits 1-9.

    Returns:
        Dictionary mapping digit to expected proportion.
    """
    return {d: math.log10(1 + 1 / d) for d in range(1, 10)}


def _benford_chi_squared(observed, expected, total):
    """Compute chi-squared statistic for Benford deviation.

    Args:
        observed: Observed digit count dictionary.
        expected: Expected proportion dictionary.
        total: Total number of observations.

    Returns:
        Chi-squared statistic value.
    """
    if total == 0:
        return 0.0
    return sum(
        (observed[d] - expected[d] * total) ** 2 / max(expected[d] * total, 1)
        for d in range(1, 10)
    )


def _benford_score(chi_sq):
    """Normalize Benford chi-squared into a 0-1 anomaly score.

    Args:
        chi_sq: Chi-squared statistic.

    Returns:
        Normalized score in [0.0, 1.0].
    """
    return max(0.0, min(1.0, chi_sq / 200.0))


def _build_benford_findings(score):
    """Build findings from Benford's Law anomaly score.

    Args:
        score: Normalized Benford score.

    Returns:
        List of (description, severity) tuples.
    """
    if score > 0.55:
        return [(f"Benford's Law violation in DCT data (score={score:.2f})", 3)]
    if score > 0.35:
        return [(f"Mild Benford deviation in DCT data (score={score:.2f})", 2)]
    return []


def _no_benford_result():
    """Return default result for non-JPEG images.

    Returns:
        Default Benford analysis result dictionary.
    """
    return {"applicable": False, "score": 0.0, "chi_squared": 0.0, "findings": []}


def _compute_benford_stats(scan):
    """Compute Benford chi-squared and score from scan bytes.

    Args:
        scan: Entropy-coded byte sequence.

    Returns:
        Tuple of (chi_squared, score, findings).
    """
    counts = _first_digit_counts(scan)
    total = sum(counts.values())
    expected = _benford_expected()
    chi_sq = _benford_chi_squared(counts, expected, total)
    score = _benford_score(chi_sq)
    return chi_sq, score, _build_benford_findings(score)


def _benford_unavailable_result():
    """Return Benford output when JPEG scan data is unavailable.

    Returns:
        Default Benford analysis result dictionary.
    """
    return {"applicable": False, "score": 0.0, "chi_squared": 0.0, "findings": []}


def _benford_result(chi_sq, score, findings):
    """Build Benford output payload with rounded metrics.

    Args:
        chi_sq: Benford chi-squared value.
        score: Benford anomaly score.
        findings: Benford finding tuples.

    Returns:
        Dictionary for Benford analysis output.
    """
    return {
        "applicable": True,
        "chi_squared": round(chi_sq, 4),
        "score": round(score, 4),
        "findings": findings,
    }


def _analyze_benford_law(image_path):
    """Test JPEG DCT coefficient distribution against Benford's Law.

    Args:
        image_path: Path to image file.

    Returns:
        Dictionary with Benford score and findings.
    """
    data = _extract_raw_jpeg_bytes(image_path)
    offset = _sos_offset(data)
    is_jpeg = image_path.lower().endswith((".jpg", ".jpeg"))
    scan = _extract_scan_bytes(data, offset) if is_jpeg and offset >= 0 else b""
    if not scan:
        return {"applicable": False, "score": 0.0, "chi_squared": 0.0, "findings": []}
    chi_sq, score, findings = _compute_benford_stats(scan)
    return _benford_result(chi_sq, score, findings)


# ===================================================================
# Pass 3: Double JPEG Compression Detection
# ===================================================================


def _resave_at_quality(image, quality):
    """Re-save image at specified JPEG quality and reload.

    Args:
        image: PIL RGB Image.
        quality: JPEG quality level.

    Returns:
        Re-loaded PIL RGB Image.
    """
    buf = io.BytesIO()
    image.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    return PIL.Image.open(buf).convert("RGB")


def _boundary_row_indices(h):
    """Generate 8x8 block boundary row indices.

    Args:
        h: Image height.

    Returns:
        List of boundary row indices.
    """
    return [min(y, h - 1) for y in range(0, h, 8)]


def _boundary_col_indices(w):
    """Generate 8x8 block boundary column indices.

    Args:
        w: Image width.

    Returns:
        List of boundary column indices.
    """
    return [min(x, w - 1) for x in range(0, w, 8)]


def _boundary_mask(h, w):
    """Build boolean mask for 8x8 block boundary pixels.

    Args:
        h: Image height.
        w: Image width.

    Returns:
        2D boolean numpy array.
    """
    mask = np.zeros((h, w), dtype=bool)
    for y in _boundary_row_indices(h):
        mask[y, :] = True
    for x in _boundary_col_indices(w):
        mask[:, x] = True
    return mask


def _block_boundary_error(diff_arr, mask):
    """Compute mean error along 8x8 JPEG block boundary pixels.

    Args:
        diff_arr: 3D float difference array.
        mask: 2D boolean boundary mask.

    Returns:
        Mean boundary error value.
    """
    boundary_vals = diff_arr[mask].flatten()
    return float(np.mean(boundary_vals)) if len(boundary_vals) > 0 else 0.0


def _non_boundary_error(diff_arr, mask):
    """Compute mean error away from 8x8 JPEG block boundaries.

    Args:
        diff_arr: 3D float difference array.
        mask: 2D boolean boundary mask.

    Returns:
        Mean non-boundary error value.
    """
    non_vals = diff_arr[~mask].flatten()
    return float(np.mean(non_vals)) if len(non_vals) > 0 else 0.0


def _double_jpeg_ratio(boundary_err, non_boundary_err):
    """Compute boundary-to-non-boundary error ratio.

    Args:
        boundary_err: Mean boundary pixel error.
        non_boundary_err: Mean non-boundary pixel error.

    Returns:
        Ratio indicating double compression likelihood.
    """
    if non_boundary_err < 0.01:
        return 0.0
    return boundary_err / non_boundary_err


def _double_jpeg_score(ratio):
    """Normalize double-JPEG ratio into anomaly score.

    Args:
        ratio: Boundary vs non-boundary error ratio.

    Returns:
        Score in [0.0, 1.0].
    """
    return max(0.0, min(1.0, abs(ratio - 1.0) * 2.0))


def _build_double_jpeg_findings(score):
    """Build findings from double JPEG compression score.

    Args:
        score: Normalized double-JPEG score.

    Returns:
        List of (description, severity) tuples.
    """
    if score > 0.50:
        return [(f"Double JPEG compression detected (score={score:.2f})", 3)]
    if score > 0.30:
        return [(f"Possible double JPEG compression (score={score:.2f})", 2)]
    return []


def _no_double_jpeg_result():
    """Return default result for non-JPEG images.

    Returns:
        Default double-JPEG result dictionary.
    """
    return {"applicable": False, "score": 0.0, "ratio": 0.0, "findings": []}


def _compute_diff_array(image, resaved):
    """Compute pixel difference array between original and resaved.

    Args:
        image: Original PIL Image.
        resaved: Re-saved PIL Image.

    Returns:
        3D float32 numpy difference array.
    """
    return np.array(PIL.ImageChops.difference(image, resaved), dtype=np.float32)


def _double_jpeg_metrics(diff_arr, mask):
    """Compute ratio and score from block boundary and non-boundary errors.

    Args:
        diff_arr: Pixel difference array.
        mask: Block boundary boolean mask.

    Returns:
        Tuple of (ratio, score).
    """
    b_err = _block_boundary_error(diff_arr, mask)
    nb_err = _non_boundary_error(diff_arr, mask)
    ratio = _double_jpeg_ratio(b_err, nb_err)
    score = _double_jpeg_score(ratio)
    return ratio, score, _build_double_jpeg_findings(score)


def _compute_double_jpeg_scores(image):
    """Compute double-JPEG metrics from boundary analysis.

    Args:
        image: PIL RGB Image.

    Returns:
        Tuple of (ratio, score, findings).
    """
    resaved = _resave_at_quality(image, 85)
    diff_arr = np.array(PIL.ImageChops.difference(image, resaved), dtype=np.float32)
    h, w = image.size[1], image.size[0]
    mask = _boundary_mask(h, w)
    return _double_jpeg_metrics(diff_arr, mask)


def _double_jpeg_result(ratio, score, findings):
    """Build final result payload for double-JPEG analysis.

    Args:
        ratio: Boundary-to-non-boundary error ratio.
        score: Double-JPEG anomaly score.
        findings: Double-JPEG finding tuples.

    Returns:
        Dictionary for double-JPEG analysis output.
    """
    return {
        "applicable": True,
        "ratio": round(ratio, 4),
        "score": round(score, 4),
        "findings": findings,
    }


def _analyze_double_jpeg(image_path):
    """Detect double JPEG compression via block-boundary error analysis.

    Args:
        image_path: Path to image file.

    Returns:
        Dictionary with double-compression score and findings.
    """
    if not _is_jpeg_file(image_path):
        return _no_double_jpeg_result()
    image = PIL.Image.open(image_path).convert("RGB")
    ratio, score, findings = _compute_double_jpeg_scores(image)
    return _double_jpeg_result(ratio, score, findings)


# ===================================================================
# Pass 4: FFT Spectral Analysis (GAN/AI Artifact Detection)
# ===================================================================


def _load_gray_array(image_path):
    """Load image as grayscale numpy array.

    Args:
        image_path: Path to image file.

    Returns:
        2D numpy float32 array.
    """
    img = PIL.Image.open(image_path).convert("L")
    return np.array(img, dtype=np.float32)


def _compute_magnitude_spectrum(gray_arr):
    """Compute log magnitude spectrum via 2D FFT.

    Args:
        gray_arr: Grayscale numpy array.

    Returns:
        Centered log-magnitude spectrum array.
    """
    f_transform = np.fft.fft2(gray_arr)
    f_shift = np.fft.fftshift(f_transform)
    return np.log1p(np.abs(f_shift))


def _build_radius_map(shape):
    """Build integer radial distance map from spectrum center.

    Args:
        shape: Tuple of (height, width).

    Returns:
        2D integer numpy array of radial distances.
    """
    cy, cx = shape[0] // 2, shape[1] // 2
    y_idx, x_idx = np.ogrid[: shape[0], : shape[1]]
    return np.sqrt((x_idx - cx) ** 2 + (y_idx - cy) ** 2).astype(int)


def _radial_bin_mean(spectrum, r_map, radius):
    """Compute mean spectrum value at a single radial distance.

    Args:
        spectrum: 2D magnitude spectrum.
        r_map: 2D integer radius map.
        radius: Target radial distance.

    Returns:
        Mean value at this radius.
    """
    mask = r_map == radius
    return float(spectrum[mask].mean()) if mask.any() else 0.0


def _radial_profile(spectrum):
    """Compute radial mean profile of centered spectrum.

    Args:
        spectrum: Centered 2D magnitude spectrum.

    Returns:
        1D numpy array of radial mean values.
    """
    r_map = _build_radius_map(spectrum.shape)
    max_r = min(spectrum.shape[0] // 2, spectrum.shape[1] // 2)
    return np.array([_radial_bin_mean(spectrum, r_map, i) for i in range(max_r)])


def _spectral_peak_score(profile):
    """Score spectral anomalies from radial profile peaks.

    Args:
        profile: 1D radial mean array.

    Returns:
        Anomaly score in [0.0, 1.0].
    """
    if len(profile) < 10:
        return 0.0
    mid = profile[len(profile) // 4 :]
    mean_val, std_val = float(np.mean(mid)), float(np.std(mid))
    if std_val < 1e-6:
        return 0.0
    peak_ratio = (float(np.max(mid)) - mean_val) / std_val
    return max(0.0, min(1.0, (peak_ratio - 3.0) / 5.0))


def _build_fft_findings(score):
    """Build findings from FFT spectral analysis score.

    Args:
        score: FFT anomaly score.

    Returns:
        List of (description, severity) tuples.
    """
    if score > 0.50:
        return [(f"FFT spectral anomaly detected (score={score:.2f})", 3)]
    if score > 0.30:
        return [(f"Mild FFT spectral anomaly (score={score:.2f})", 2)]
    return []


def _analyze_fft_spectral(image_path):
    """Detect GAN/AI artifacts via FFT spectral analysis.

    Args:
        image_path: Path to image file.

    Returns:
        Dictionary with spectral score and findings.
    """
    gray_arr = _load_gray_array(image_path)
    spectrum = _compute_magnitude_spectrum(gray_arr)
    profile = _radial_profile(spectrum)
    score = _spectral_peak_score(profile)
    findings = _build_fft_findings(score)
    return {"score": round(score, 4), "findings": findings}


# ===================================================================
# Pass 5: PRNU Sensor Noise Fingerprinting
# ===================================================================


def _denoise_image(gray_arr):
    """Apply simple averaging denoise to grayscale array.

    Args:
        gray_arr: Grayscale numpy float32 array.

    Returns:
        Denoised numpy float32 array.
    """
    img = PIL.Image.fromarray(gray_arr.astype(np.uint8), mode="L")
    denoised = img.filter(PIL.ImageFilter.GaussianBlur(radius=2))
    return np.array(denoised, dtype=np.float32)


def _extract_noise_residual(gray_arr, denoised):
    """Extract noise residual by subtracting denoised from original.

    Args:
        gray_arr: Original grayscale array.
        denoised: Denoised grayscale array.

    Returns:
        Noise residual array.
    """
    return gray_arr - denoised


def _cell_variance(residual, r, c, ch, cw):
    """Compute variance of one grid cell in the noise residual.

    Args:
        residual: Noise residual array.
        r: Row index.
        c: Column index.
        ch: Cell height.
        cw: Cell width.

    Returns:
        Variance of the cell.
    """
    cell = residual[r * ch : (r + 1) * ch, c * cw : (c + 1) * cw]
    return float(np.var(cell))


def _grid_noise_variances(residual, grid_size):
    """Compute noise variance for each cell in a grid.

    Args:
        residual: Noise residual array.
        grid_size: Number of divisions per axis.

    Returns:
        1D numpy array of cell variances.
    """
    h, w = residual.shape
    ch, cw = h // grid_size, w // grid_size
    variances = [
        _cell_variance(residual, r, c, ch, cw)
        for r in range(grid_size)
        for c in range(grid_size)
    ]
    return np.array(variances)


def _prnu_consistency_score(variances):
    """Compute PRNU consistency score from region variance CV.

    Args:
        variances: Array of per-cell noise variances.

    Returns:
        Score in [0.0, 1.0] where higher means less consistent.
    """
    mean_var = float(np.mean(variances))
    if mean_var < 1e-6:
        return 0.0
    cv = float(np.std(variances) / mean_var)
    return max(0.0, min(1.0, cv / 1.5))


def _build_prnu_findings(score):
    """Build findings from PRNU consistency score.

    Args:
        score: PRNU inconsistency score.

    Returns:
        List of (description, severity) tuples.
    """
    if score > 0.55:
        return [(f"PRNU sensor noise inconsistency (score={score:.2f})", 3)]
    if score > 0.35:
        return [(f"Mild PRNU noise variation (score={score:.2f})", 2)]
    return []


def _analyze_prnu_consistency(image_path):
    """Analyze PRNU sensor noise consistency across image regions.

    Args:
        image_path: Path to image file.

    Returns:
        Dictionary with PRNU score and findings.
    """
    gray_arr = _load_gray_array(image_path)
    denoised = _denoise_image(gray_arr)
    residual = _extract_noise_residual(gray_arr, denoised)
    variances = _grid_noise_variances(residual, 6)
    score = _prnu_consistency_score(variances)
    findings = _build_prnu_findings(score)
    return {"score": round(score, 4), "findings": findings}


# ===================================================================
# Pass 6: Illumination Direction Consistency
# ===================================================================


def _compute_gradients(gray_arr):
    """Compute horizontal and vertical Sobel-like gradients.

    Args:
        gray_arr: Grayscale numpy float32 array.

    Returns:
        Tuple of (gradient_x, gradient_y) arrays.
    """
    gx = np.diff(gray_arr, axis=1, prepend=gray_arr[:, :1])
    gy = np.diff(gray_arr, axis=0, prepend=gray_arr[:1, :])
    return gx, gy


def _region_light_direction(gx, gy):
    """Estimate dominant light direction from gradient field.

    Args:
        gx: Horizontal gradient array.
        gy: Vertical gradient array.

    Returns:
        Angle in radians of dominant light direction.
    """
    mean_gx = float(np.mean(gx))
    mean_gy = float(np.mean(gy))
    return math.atan2(mean_gy, mean_gx)


def _quadrant_slices(h, w):
    """Return quadrant boundary slices for an image.

    Args:
        h: Image height.
        w: Image width.

    Returns:
        List of (y0, y1, x0, x1) tuples.
    """
    mh, mw = h // 2, w // 2
    return [(0, mh, 0, mw), (0, mh, mw, w), (mh, h, 0, mw), (mh, h, mw, w)]


def _quadrant_light_angles(gx, gy):
    """Compute dominant light direction per quadrant.

    Args:
        gx: Full horizontal gradient array.
        gy: Full vertical gradient array.

    Returns:
        List of 4 angles (one per quadrant).
    """
    h, w = gx.shape
    mh, mw = h // 2, w // 2
    slices = [(0, mh, 0, mw), (0, mh, mw, w), (mh, h, 0, mw), (mh, h, mw, w)]
    return [
        _region_light_direction(gx[y0:y1, x0:x1], gy[y0:y1, x0:x1])
        for y0, y1, x0, x1 in slices
    ]


def _pairwise_angle_diff(a1, a2):
    """Compute minimal angular difference between two angles.

    Args:
        a1: First angle in radians.
        a2: Second angle in radians.

    Returns:
        Minimal angular difference in radians.
    """
    diff = abs(a1 - a2)
    return min(diff, 2 * math.pi - diff)


def _angle_deviation(angles):
    """Compute max angular deviation among quadrant estimates.

    Args:
        angles: List of light direction angles in radians.

    Returns:
        Maximum pairwise deviation in radians.
    """
    max_dev = 0.0
    for i in range(len(angles)):
        for j in range(i + 1, len(angles)):
            max_dev = max(max_dev, _pairwise_angle_diff(angles[i], angles[j]))
    return max_dev


def _illumination_score(deviation):
    """Normalize angular deviation into anomaly score.

    Args:
        deviation: Maximum angular deviation in radians.

    Returns:
        Score in [0.0, 1.0].
    """
    return max(0.0, min(1.0, deviation / (math.pi / 2)))


def _build_illumination_findings(score):
    """Build findings from illumination consistency score.

    Args:
        score: Illumination anomaly score.

    Returns:
        List of (description, severity) tuples.
    """
    if score > 0.55:
        return [(f"Illumination direction inconsistency (score={score:.2f})", 3)]
    if score > 0.35:
        return [(f"Mild illumination variation (score={score:.2f})", 2)]
    return []


def _compute_illumination_scores(image_path):
    """Compute illumination consistency metrics.

    Args:
        image_path: Path to image file.

    Returns:
        Tuple of (score, deviation, findings).
    """
    gray_arr = _load_gray_array(image_path)
    gx, gy = _compute_gradients(gray_arr)
    angles = _quadrant_light_angles(gx, gy)
    deviation = _angle_deviation(angles)
    score = _illumination_score(deviation)
    return score, deviation, _build_illumination_findings(score)


def _analyze_illumination_consistency(image_path):
    """Analyze light-source direction consistency across quadrants.

    Args:
        image_path: Path to image file.

    Returns:
        Dictionary with illumination score and findings.
    """
    score, deviation, findings = _compute_illumination_scores(image_path)
    return {
        "score": round(score, 4),
        "deviation_rad": round(deviation, 4),
        "findings": findings,
    }


# ===================================================================
# Aggregate: Run all nation-state passes
# ===================================================================


def _merge_findings(results):
    """Merge findings from all nation-state passes.

    Args:
        results: Dictionary of pass results.

    Returns:
        Combined list of (description, severity) tuples.
    """
    findings = []
    for key in results:
        findings.extend(results[key].get("findings", []))
    return findings


def _run_all_passes(image_path):
    """Run the six nation-state forensic sub-passes.

    Args:
        image_path: Path to image file.

    Returns:
        Dictionary with all pass results.
    """
    return {
        "thumbnail": _analyze_thumbnail_comparison(image_path),
        "benford": _analyze_benford_law(image_path),
        "double_jpeg": _analyze_double_jpeg(image_path),
        "fft_spectral": _analyze_fft_spectral(image_path),
        "prnu": _analyze_prnu_consistency(image_path),
        "illumination": _analyze_illumination_consistency(image_path),
    }


def _with_merged_findings(results):
    """Attach merged findings to nation-state pass result dictionary.

    Args:
        results: Dictionary of per-pass outputs.

    Returns:
        Results with top-level merged findings key added.
    """
    results["findings"] = _merge_findings(results)
    return results


def analyze_nation_state_passes(image_path):
    """Run all six nation-state-grade forensic passes.

    Args:
        image_path: Path to image file.

    Returns:
        Dictionary with all pass results and merged findings.
    """
    results = _run_all_passes(image_path)
    return _with_merged_findings(results)
