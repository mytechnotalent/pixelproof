#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advanced forensic analysis engine for PixelProof.

This module adds higher-order forensic passes and returns structured evidence
that can be fused into deep analysis findings and reports.
"""

import io
import math
from collections import Counter

import PIL.Image
import PIL.ImageChops
import PIL.ImageStat


def _load_gray_image(image_path):
    """Load an image as grayscale for luminance-domain analysis.

    Args:
        image_path: Path to the image file.

    Returns:
        A grayscale PIL image.
    """
    return PIL.Image.open(image_path).convert("L")


def _histogram_empty_ratio(hist):
    """Compute the ratio of empty histogram bins.

    Args:
        hist: 256-bin grayscale histogram.

    Returns:
        Fraction of bins with zero count.
    """
    return sum(1 for value in hist if value == 0) / 256.0


def _histogram_pair_comb_ratio(hist):
    """Measure odd/even bin imbalance as combing indicator.

    Args:
        hist: 256-bin grayscale histogram.

    Returns:
        Average normalized odd-even pair difference.
    """
    diffs = [
        abs(hist[i] - hist[i + 1]) / max(hist[i] + hist[i + 1], 1)
        for i in range(0, 256, 2)
    ]
    return sum(diffs) / len(diffs)


def _histogram_score(empty_ratio, comb_ratio):
    """Fuse histogram anomaly metrics into a normalized score.

    Args:
        empty_ratio: Ratio of empty bins.
        comb_ratio: Odd/even pair imbalance score.

    Returns:
        Score in range [0.0, 1.0].
    """
    return max(0.0, min(1.0, 0.55 * empty_ratio + 0.45 * comb_ratio))


def _build_histogram_findings(score):
    """Create histogram-based forensic findings from score thresholding.

    Args:
        score: Histogram anomaly score.

    Returns:
        List of (description, severity) tuples.
    """
    if score >= 0.40:
        return [(f"Histogram combing artifacts detected (score={score:.2f})", 2)]
    if score >= 0.28:
        return [(f"Mild histogram discontinuity detected (score={score:.2f})", 1)]
    return []


def _analyze_histogram_forensics(gray):
    """Analyze grayscale histogram for post-processing artifacts.

    Args:
        gray: Grayscale PIL image.

    Returns:
        Result dictionary with score and findings.
    """
    hist = gray.histogram()
    empty_ratio = _histogram_empty_ratio(hist)
    comb_ratio = _histogram_pair_comb_ratio(hist)
    score = _histogram_score(empty_ratio, comb_ratio)
    findings = _build_histogram_findings(score)
    return {
        "empty_ratio": round(empty_ratio, 4),
        "comb_ratio": round(comb_ratio, 4),
        "score": round(score, 4),
        "findings": findings,
    }


def _gradient_cell_means(gray, grid):
    """Compute mean gradient magnitude for each grid cell.

    Args:
        gray: Grayscale PIL image.
        grid: Number of grid divisions per axis.

    Returns:
        List of cell mean gradient magnitudes.
    """
    w, h = gray.size
    data = list(gray.getdata())
    cw, ch = max(2, w // grid), max(2, h // grid)
    return [
        _cell_gradient_mean(data, w, h, r * ch, c * cw, ch, cw)
        for r in range(grid)
        for c in range(grid)
    ]


def _cell_gradient_mean(data, width, height, y0, x0, cell_h, cell_w):
    """Estimate average gradient magnitude inside one rectangular cell.

    Args:
        data: Flat grayscale pixel list.
        width: Image width in pixels.
        height: Image height in pixels.
        y0: Cell top origin.
        x0: Cell left origin.
        cell_h: Cell height.
        cell_w: Cell width.

    Returns:
        Mean gradient magnitude for the cell.
    """
    y1, x1 = min(height - 1, y0 + cell_h - 1), min(width - 1, x0 + cell_w - 1)
    grads = [
        abs(data[y * width + x] - data[y * width + x + 1])
        + abs(data[y * width + x] - data[(y + 1) * width + x])
        for y in range(y0, y1)
        for x in range(x0, x1)
    ]
    return sum(grads) / max(len(grads), 1)


def _gradient_cv(values):
    """Compute coefficient of variation for gradient cell means.

    Args:
        values: Sequence of mean gradient values.

    Returns:
        Coefficient of variation.
    """
    mean_val = sum(values) / max(len(values), 1)
    variance = sum((value - mean_val) ** 2 for value in values) / max(len(values), 1)
    return (math.sqrt(variance) / mean_val) if mean_val > 0 else 0.0


def _build_gradient_findings(cv):
    """Create luminance-gradient consistency findings.

    Args:
        cv: Coefficient of variation for gradient field.

    Returns:
        List of (description, severity) tuples.
    """
    if cv > 0.55:
        return [(f"Luminance-gradient inconsistency is high (CV={cv:.2f})", 2)]
    if cv > 0.40:
        return [(f"Luminance-gradient inconsistency is moderate (CV={cv:.2f})", 1)]
    return []


def _analyze_gradient_consistency(gray):
    """Analyze gradient-field consistency across image regions.

    Args:
        gray: Grayscale PIL image.

    Returns:
        Result dictionary with gradient CV and findings.
    """
    cell_means = _gradient_cell_means(gray, 6)
    cv = _gradient_cv(cell_means)
    findings = _build_gradient_findings(cv)
    return {"grid": 6, "gradient_cv": round(cv, 4), "findings": findings}


def _iter_block_hashes(gray, block, stride):
    """Generate perceptual hashes for overlapping grayscale blocks.

    Args:
        gray: Grayscale PIL image.
        block: Block edge size in pixels.
        stride: Sliding window stride in pixels.

    Returns:
        Iterator over block hash strings.
    """
    w, h = gray.size
    for y in range(0, max(h - block + 1, 1), stride):
        for x in range(0, max(w - block + 1, 1), stride):
            crop = gray.crop((x, y, x + block, y + block)).resize((8, 8))
            yield _block_hash(crop)


def _block_hash(block_img):
    """Compute a simple binary mean-threshold block hash.

    Args:
        block_img: Small grayscale PIL image block.

    Returns:
        Hash string representing coarse local texture.
    """
    pixels = list(block_img.getdata())
    mean_val = sum(pixels) / max(len(pixels), 1)
    return "".join("1" if p >= mean_val else "0" for p in pixels)


def _copy_move_duplicate_ratio(gray):
    """Estimate duplicate-texture ratio as copy-move evidence.

    Args:
        gray: Grayscale PIL image.

    Returns:
        Duplicate ratio in [0.0, 1.0].
    """
    hashes = list(_iter_block_hashes(gray, 16, 8))
    counts = Counter(hashes)
    duplicated = sum(count - 1 for count in counts.values() if count > 1)
    return duplicated / max(len(hashes), 1)


def _build_copy_move_findings(ratio):
    """Create copy-move findings from duplicate block ratio.

    Args:
        ratio: Ratio of duplicated block hashes.

    Returns:
        List of (description, severity) tuples.
    """
    if ratio > 0.18:
        return [(f"Copy-move pattern detected (duplicate ratio={ratio:.2f})", 3)]
    if ratio > 0.11:
        return [(f"Possible copy-move traces (duplicate ratio={ratio:.2f})", 2)]
    return []


def _analyze_copy_move(gray):
    """Analyze self-similarity to detect cloning/copy-move traces.

    Args:
        gray: Grayscale PIL image.

    Returns:
        Result dictionary with duplicate ratio and findings.
    """
    ratio = _copy_move_duplicate_ratio(gray)
    findings = _build_copy_move_findings(ratio)
    return {"duplicate_ratio": round(ratio, 4), "findings": findings}


def _jpeg_candidate_qualities():
    """Provide quality sweep candidates for JPEG ghost analysis.

    Returns:
        Quality integer list.
    """
    return [55, 65, 75, 85, 92, 96]


def _jpeg_diff_mean(image, quality):
    """Compute mean absolute difference after JPEG re-save.

    Args:
        image: RGB PIL image.
        quality: JPEG quality level.

    Returns:
        Mean RGB difference magnitude.
    """
    buf = io.BytesIO()
    image.save(buf, "JPEG", quality=quality)
    diff = PIL.ImageChops.difference(
        image, PIL.Image.open(io.BytesIO(buf.getvalue())).convert("RGB")
    )
    return sum(PIL.ImageStat.Stat(diff).mean) / 3.0


def _ghost_quality_profile(image):
    """Compute quality-to-difference profile for JPEG ghost signal.

    Args:
        image: RGB PIL image.

    Returns:
        List of dictionaries with quality and mean_diff.
    """
    qualities = _jpeg_candidate_qualities()
    return [
        {"quality": q, "mean_diff": round(_jpeg_diff_mean(image, q), 4)}
        for q in qualities
    ]


def _ghost_profile_score(profile):
    """Compute normalized instability score for quality profile.

    Args:
        profile: List of quality profile entries.

    Returns:
        Score in range [0.0, 1.0].
    """
    means = [item["mean_diff"] for item in profile]
    std = math.sqrt(
        sum((m - (sum(means) / len(means))) ** 2 for m in means) / max(len(means), 1)
    )
    return max(0.0, min(1.0, std / max(sum(means) / len(means), 1e-6)))


def _build_ghost_findings(score):
    """Create JPEG ghost findings from profile instability score.

    Args:
        score: JPEG ghost instability score.

    Returns:
        List of (description, severity) tuples.
    """
    if score > 0.42:
        return [(f"JPEG ghosting signature detected (score={score:.2f})", 2)]
    if score > 0.30:
        return [(f"Mild JPEG ghost instability detected (score={score:.2f})", 1)]
    return []


def _analyze_jpeg_ghost(image_path):
    """Analyze JPEG ghost artifacts by quality re-save instability.

    Args:
        image_path: Path to the image file.

    Returns:
        Result dictionary with profile, score, and findings.
    """
    image = PIL.Image.open(image_path).convert("RGB")
    profile = _ghost_quality_profile(image)
    score = _ghost_profile_score(profile)
    findings = _build_ghost_findings(score)
    return {"quality_profile": profile, "score": round(score, 4), "findings": findings}


def _is_jpeg_path(image_path):
    """Check if a path likely points to a JPEG image.

    Args:
        image_path: Path to inspect.

    Returns:
        True when extension indicates JPEG.
    """
    lowered = image_path.lower()
    return lowered.endswith(".jpg") or lowered.endswith(".jpeg")


def _collect_advanced_findings(results):
    """Aggregate findings from all advanced forensic sub-analyses.

    Args:
        results: Dictionary of advanced analysis outputs.

    Returns:
        Flat list of (description, severity) tuples.
    """
    findings = []
    findings.extend(results["histogram"]["findings"])
    findings.extend(results["gradient"]["findings"])
    findings.extend(results["copy_move"]["findings"])
    findings.extend(results["jpeg_ghost"]["findings"])
    return findings


def _severity_score(findings):
    """Compute normalized severity score from findings.

    Args:
        findings: List of (description, severity) tuples.

    Returns:
        Severity score in range [0.0, 1.0].
    """
    total = sum(severity for _, severity in findings)
    return max(0.0, min(1.0, total / 18.0))


def _stego_score(stego):
    """Compute steganography contribution score.

    Args:
        stego: Stego result dictionary or None.

    Returns:
        Score in range [0.0, 1.0].
    """
    if not stego:
        return 0.0
    verdict = stego.get("verdict", "")
    if "DETECTED" in verdict:
        return 1.0
    if "SUSPICIOUS" in verdict:
        return 0.65
    return 0.05


def _advanced_score(advanced):
    """Compute advanced-forensics contribution score.

    Args:
        advanced: Advanced forensics result dictionary or None.

    Returns:
        Score in range [0.0, 1.0].
    """
    if not advanced:
        return 0.0
    values = [
        advanced["histogram"]["score"],
        advanced["gradient"]["gradient_cv"],
        advanced["copy_move"]["duplicate_ratio"],
        advanced["jpeg_ghost"]["score"],
    ]
    return max(
        0.0,
        min(
            1.0, 0.2 * values[0] + 0.25 * values[1] + 0.3 * values[2] + 0.25 * values[3]
        ),
    )


def _metadata_score(exif, ps_blocks):
    """Compute metadata/provenance contribution score.

    Args:
        exif: EXIF dictionary.
        ps_blocks: Photoshop block list.

    Returns:
        Score in range [0.0, 1.0].
    """
    has_camera = bool(exif.get("Make") and exif.get("Model"))
    has_time = bool(exif.get("DateTime") or exif.get("DateTimeOriginal"))
    ps_flag = 0.6 if ps_blocks else 0.0
    missing_core = 0.6 if not (has_camera and has_time) else 0.0
    return max(0.0, min(1.0, max(ps_flag, missing_core)))


def _consistency_score(noise_cv, channels, ela_max):
    """Compute consistency-anomaly score from cross-domain signals.

    Args:
        noise_cv: Noise coefficient of variation.
        channels: Channel-correlation dictionary.
        ela_max: Maximum ELA pixel error.

    Returns:
        Score in range [0.0, 1.0].
    """
    low_corr = 1.0 - min(channels.values())
    noise_term = max(0.0, min(1.0, noise_cv / 0.6))
    ela_term = max(0.0, min(1.0, ela_max / 40.0))
    return max(0.0, min(1.0, 0.35 * noise_term + 0.35 * low_corr + 0.3 * ela_term))


def _weighted_fusion(components):
    """Fuse component scores with fixed forensic weights.

    Args:
        components: Dictionary of component scores.

    Returns:
        Weighted fused score in range [0.0, 1.0].
    """
    weights = {
        "severity": 0.22,
        "stego": 0.18,
        "advanced": 0.26,
        "metadata": 0.2,
        "consistency": 0.14,
    }
    return sum(components[name] * weights[name] for name in weights)


def _consensus_factor(components):
    """Compute consensus factor from component agreement.

    Args:
        components: Dictionary of component scores.

    Returns:
        Consensus factor in range [0.75, 1.15].
    """
    values = list(components.values())
    mean_val = sum(values) / len(values)
    variance = sum((value - mean_val) ** 2 for value in values) / len(values)
    return max(0.75, min(1.15, 1.05 - 0.45 * math.sqrt(variance)))


def _confidence_label(probability, consensus):
    """Convert probability and consensus to confidence label.

    Args:
        probability: Tamper probability in [0.0, 1.0].
        consensus: Consensus factor.

    Returns:
        Confidence label string.
    """
    if probability >= 0.85 and consensus >= 0.92:
        return "VERY HIGH"
    if probability >= 0.70 and consensus >= 0.88:
        return "HIGH"
    if probability >= 0.50:
        return "MEDIUM"
    return "LOW"


def _authenticity_verdict(probability):
    """Map tamper probability to human-readable verdict.

    Args:
        probability: Tamper probability in [0.0, 1.0].

    Returns:
        Verdict label string.
    """
    if probability >= 0.85:
        return "LIKELY ALTERED"
    if probability >= 0.65:
        return "POSSIBLY ALTERED"
    if probability >= 0.45:
        return "INCONCLUSIVE"
    return "LIKELY AUTHENTIC"


def _apply_guardrails(probability, components):
    """Apply conservative guardrails for high-risk evidence combinations.

    Args:
        probability: Raw fused tamper probability.
        components: Component score dictionary.

    Returns:
        Guardrailed tamper probability.
    """
    severity = components.get("severity", 0.0)
    metadata = components.get("metadata", 0.0)
    advanced = components.get("advanced", 0.0)
    if severity >= 0.65 and metadata >= 0.55:
        return max(probability, 0.82)
    if severity >= 0.55 and advanced >= 0.30:
        return max(probability, 0.72)
    return probability


def _build_assessment(components, fused, consensus):
    """Build final authenticity assessment dictionary.

    Args:
        components: Component score dictionary.
        fused: Weighted fused score.
        consensus: Consensus factor.

    Returns:
        Authenticity assessment dictionary.
    """
    probability = max(0.0, min(1.0, fused * consensus))
    probability = _apply_guardrails(probability, components)
    verdict = _authenticity_verdict(probability)
    confidence = _confidence_label(probability, consensus)
    return {
        "tamper_probability": round(probability, 4),
        "confidence": confidence,
        "verdict": verdict,
        "consensus": round(consensus, 4),
        "components": {name: round(value, 4) for name, value in components.items()},
    }


def _default_channels():
    """Return default neutral channel-correlation values.

    Returns:
        Channel dictionary with neutral correlation values.
    """
    return {"rg": 1.0, "rb": 1.0, "gb": 1.0}


def _component_scores(results):
    """Build all weighted component scores for authenticity fusion.

    Args:
        results: Full deep-analysis results dictionary.

    Returns:
        Component score dictionary.
    """
    findings = results.get("findings", [])
    exif = results.get("exif", {})
    channels = results.get("channels", _default_channels())
    consistency = _consistency_score(
        results.get("noise_cv", 0.0),
        channels,
        results.get("ela", {}).get("max_error", 0.0),
    )
    return {
        "severity": _severity_score(findings),
        "stego": _stego_score(results.get("stego")),
        "advanced": _advanced_score(results.get("advanced")),
        "metadata": _metadata_score(exif, results.get("ps_blocks", [])),
        "consistency": consistency,
    }


def _empty_jpeg_ghost_result():
    """Build the default JPEG-ghost result for non-JPEG images.

    Returns:
        Default JPEG ghost result dictionary.
    """
    return {"quality_profile": [], "score": 0.0, "findings": []}


def _select_jpeg_ghost_result(image_path):
    """Select JPEG ghost analysis result based on file type.

    Args:
        image_path: Path to the image file.

    Returns:
        JPEG ghost result dictionary.
    """
    if _is_jpeg_path(image_path):
        return _analyze_jpeg_ghost(image_path)
    return _empty_jpeg_ghost_result()


def _build_advanced_results(histogram, gradient, copy_move, jpeg_ghost):
    """Assemble advanced forensics result dictionary.

    Args:
        histogram: Histogram forensics result.
        gradient: Gradient consistency result.
        copy_move: Copy-move result.
        jpeg_ghost: JPEG ghost result.

    Returns:
        Advanced forensics result dictionary.
    """
    return {
        "histogram": histogram,
        "gradient": gradient,
        "copy_move": copy_move,
        "jpeg_ghost": jpeg_ghost,
    }


def analyze_advanced_forensics(image_path):
    """Run advanced forensic passes and return structured evidence.

    Args:
        image_path: Path to the image file.

    Returns:
        Dictionary with pass results and merged findings list.
    """
    gray = _load_gray_image(image_path)
    histogram = _analyze_histogram_forensics(gray)
    gradient = _analyze_gradient_consistency(gray)
    copy_move = _analyze_copy_move(gray)
    jpeg_ghost = _select_jpeg_ghost_result(image_path)
    results = _build_advanced_results(histogram, gradient, copy_move, jpeg_ghost)
    results["findings"] = _collect_advanced_findings(results)
    return results


def compute_authenticity_assessment(results):
    """Compute nation-state-grade fused authenticity assessment.

    Args:
        results: Full deep-analysis results dictionary.

    Returns:
        Dictionary with probability, confidence, and component evidence.
    """
    components = _component_scores(results)
    fused = _weighted_fusion(components)
    consensus = _consensus_factor(components)
    return _build_assessment(components, fused, consensus)
