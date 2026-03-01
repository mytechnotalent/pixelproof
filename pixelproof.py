#!/usr/bin/env python3
"""
pixelproof -- Quick forensic scan of a photo's EXIF metadata and Photoshop traces.

Usage:
    python pixelproof.py <image_path>
"""

import sys
import os
import PIL.Image
import PIL.ExifTags

# ---------------------------------------------------------------------------
# Known camera EXIF field names expected in genuine photographs
# ---------------------------------------------------------------------------

CAMERA_FIELDS = [
    "Make",
    "Model",
    "LensModel",
    "FocalLength",
    "FNumber",
    "ExposureTime",
    "ISOSpeedRatings",
    "Flash",
    "ShutterSpeedValue",
    "ApertureValue",
    "BrightnessValue",
    "MeteringMode",
]

# ---------------------------------------------------------------------------
# Known image editing software identifiers
# ---------------------------------------------------------------------------

EDITING_SOFTWARE = [
    "photoshop",
    "gimp",
    "lightroom",
    "snapseed",
    "afterlight",
    "facetune",
    "picsart",
    "canva",
    "pixlr",
    "remini",
    "instagram",
    "vsco",
    "meitu",
    "beautyplus",
    "faceapp",
    "adobe",
]

PHOTOSHOP_HEADER_FLAG = "PHOTOSHOP RESOURCE BLOCK detected in file headers — image was processed through Adobe Photoshop or compatible software"
NO_CAMERA_INFO_FLAG = "NO CAMERA HARDWARE INFO — no Make, Model, Lens, ISO, etc. Real photos almost always have these"
NO_GPS_FLAG = "NO GPS DATA — could be stripped or location was off"
NO_TIMESTAMP_FLAG = "NO TIMESTAMP — real camera photos have date/time"
NO_EXIF_FLAG = (
    "NO EXIF DATA — metadata stripped or never existed (common in fakes / screenshots)"
)


# ---------------------------------------------------------------------------
# Private helpers for _check_photoshop_data (in call order)
# ---------------------------------------------------------------------------


def _ps_entry(res_id, res_val):
    """Build base Photoshop entry fields.

    Args:
        res_id: Numeric resource identifier.
        res_val: Resource payload value.

    Returns:
        Base entry dictionary.
    """
    return {
        "id": f"0x{res_id:04X}",
        "size": len(res_val) if isinstance(res_val, bytes) else 0,
    }


def _is_caption_block(res_id, res_val):
    """Check whether Photoshop block is caption-digest payload.

    Args:
        res_id: Numeric resource identifier.
        res_val: Resource payload value.

    Returns:
        True when caption digest block.
    """
    return res_id == 0x0425 and isinstance(res_val, bytes)


def _build_ps_block_entry(res_id, res_val):
    """Build a single Photoshop resource block entry dictionary.

    Args:
        res_id: The numeric resource identifier.
        res_val: The raw bytes value of the resource block.

    Returns:
        Tuple of (entry_dict, extra_flag_string_or_None).
    """
    entry = _ps_entry(res_id, res_val)
    if not _is_caption_block(res_id, res_val):
        return entry, None
    entry["caption_digest"] = res_val.hex()
    if entry["caption_digest"] != "d41d8cd98f00b204e9800998ecf8427e":
        return entry, None
    entry["note"] = "MD5 of empty string — caption was deliberately blanked"
    return entry, "Caption Digest is MD5('') — metadata was intentionally scrubbed"


# ---------------------------------------------------------------------------
# Private helpers for _init_report (in call order)
# ---------------------------------------------------------------------------


def _get_exif(image):
    """Return raw EXIF dictionary from a PIL Image, or None if absent.

    Args:
        image: An opened PIL Image object.

    Returns:
        Dictionary of raw EXIF tag data, or None.
    """
    return image._getexif()


def _extract_file_details(img):
    """Extract basic file-level details from a PIL Image.

    Args:
        img: An opened PIL Image object.

    Returns:
        Dictionary with format, mode, size, and info_keys.
    """
    return {
        "format": img.format,
        "mode": img.mode,
        "size": f"{img.size[0]} x {img.size[1]}",
        "info_keys": list(img.info.keys()),
    }


def _collect_ps_data(ps_data):
    """Collect parsed Photoshop blocks and extra flags from dict payload.

    Args:
        ps_data: Photoshop metadata payload.

    Returns:
        Tuple of (extra_flags, blocks).
    """
    if not isinstance(ps_data, dict):
        return [], []
    pairs = [
        _build_ps_block_entry(res_id, res_val) for res_id, res_val in ps_data.items()
    ]
    return [flag for _, flag in pairs if flag], [entry for entry, _ in pairs]


def _check_photoshop_data(img):
    """Check for Photoshop resource blocks in the image file headers.

    Args:
        img: An opened PIL Image object.

    Returns:
        Tuple of (flags_list, photoshop_blocks_list).
    """
    flags, blocks = [], []
    ps_data = img.info.get("photoshop")
    if not ps_data:
        return flags, blocks
    flags.append(PHOTOSHOP_HEADER_FLAG)
    extra_flags, blocks = _collect_ps_data(ps_data)
    flags.extend(extra_flags)
    return flags, blocks


def _init_report(img):
    """Initialize the analysis report with file details and Photoshop checks.

    Args:
        img: An opened PIL Image object.

    Returns:
        Report dictionary with initial flags, details, and photoshop_blocks.
    """
    details = _extract_file_details(img)
    ps_flags, ps_blocks = _check_photoshop_data(img)
    return {"flags": ps_flags, "details": details, "photoshop_blocks": ps_blocks}


# ---------------------------------------------------------------------------
# Private helpers for _add_exif_flags (in call order)
# ---------------------------------------------------------------------------


def _readable_exif(raw):
    """Map numeric EXIF tag IDs to human-readable tag names.

    Args:
        raw: Dictionary of {tag_id: value} from PIL EXIF data.

    Returns:
        Dictionary of {human_readable_name: value}.
    """
    return {PIL.ExifTags.TAGS.get(t, t): v for t, v in raw.items()}


def _check_camera_fields(meta):
    """Check for missing camera hardware fields in EXIF metadata.

    Args:
        meta: Dictionary of human-readable EXIF tags.

    Returns:
        List of flag strings for missing camera data.
    """
    present = [field for field in CAMERA_FIELDS if field in meta]
    missing = [field for field in CAMERA_FIELDS if field not in meta]
    if not present:
        return [NO_CAMERA_INFO_FLAG]
    if len(missing) > len(present):
        return [f"SPARSE CAMERA DATA — missing: {', '.join(missing)}"]
    return []


def _check_editing_software(meta):
    """Check if EXIF Software tag contains known editing software names.

    Args:
        meta: Dictionary of human-readable EXIF tags.

    Returns:
        List of flag strings if editing software is detected.
    """
    software = str(meta.get("Software", "")).lower()
    for tool in EDITING_SOFTWARE:
        if tool in software:
            return [f"EDITING SOFTWARE DETECTED \u2014 '{meta.get('Software')}'"]
    return []


def _check_resolution_mismatch(meta):
    """Check if X and Y resolution values differ.

    Args:
        meta: Dictionary of human-readable EXIF tags.

    Returns:
        A flag string if mismatch detected, or None.
    """
    xres, yres = meta.get("XResolution", 0), meta.get("YResolution", 0)
    if xres and yres and xres != yres:
        return f"RESOLUTION MISMATCH \u2014 X={xres} vs Y={yres}"
    return None


def _check_orientation_flag(meta):
    """Check if the Orientation tag is missing from EXIF data.

    Args:
        meta: Dictionary of human-readable EXIF tags.

    Returns:
        A flag string if orientation is absent, or None.
    """
    if "Orientation" not in meta:
        return "NO ORIENTATION TAG \u2014 cameras always set this"
    return None


def _timestamp_from_meta(meta):
    """Extract preferred EXIF timestamp value.

    Args:
        meta: Dictionary of human-readable EXIF tags.

    Returns:
        Timestamp value or None.
    """
    return (
        meta.get("DateTime")
        or meta.get("DateTimeOriginal")
        or meta.get("DateTimeDigitized")
    )


def _check_gps_and_timestamp(meta):
    """Check for missing GPS data and timestamp in EXIF metadata.

    Args:
        meta: Dictionary of human-readable EXIF tags.

    Returns:
        Tuple of (flags_list, timestamp_string_or_None).
    """
    flags = [] if meta.get("GPSInfo") else [NO_GPS_FLAG]
    dt = _timestamp_from_meta(meta)
    if not dt:
        flags.append(NO_TIMESTAMP_FLAG)
    return flags, str(dt) if dt else None


def _check_metadata_anomalies(meta):
    """Check for resolution, orientation, GPS, and timestamp anomalies.

    Args:
        meta: Dictionary of human-readable EXIF tags.

    Returns:
        Tuple of (flags_list, timestamp_or_None).
    """
    flags = [
        flag
        for flag in [_check_resolution_mismatch(meta), _check_orientation_flag(meta)]
        if flag
    ]
    gps_flags, timestamp = _check_gps_and_timestamp(meta)
    flags.extend(gps_flags)
    return flags, timestamp


def _add_exif_flags(meta, report):
    """Add camera field, editing software, and anomaly flags to the report.

    Args:
        meta: Dictionary of human-readable EXIF tags.
        report: Report dictionary to update with flags.
    """
    report["flags"].extend(_check_camera_fields(meta))
    report["flags"].extend(_check_editing_software(meta))
    anomaly_flags, timestamp = _check_metadata_anomalies(meta)
    report["flags"].extend(anomaly_flags)
    if timestamp:
        report["details"]["timestamp"] = timestamp


def _analyze_exif(raw, report):
    """Analyze EXIF metadata and add findings to the report.

    Args:
        raw: Raw EXIF dictionary from PIL, or None.
        report: Existing report dictionary to update.

    Returns:
        Updated report dictionary.
    """
    if not raw:
        report["flags"].append(NO_EXIF_FLAG)
        return report
    meta = _readable_exif(raw)
    report["details"].update(meta)
    _add_exif_flags(meta, report)
    return report


def _analyze_metadata(image_path):
    """Perform full metadata analysis on an image file.

    Args:
        image_path: Path to the image file to analyze.

    Returns:
        Report dictionary with 'flags', 'details', and 'photoshop_blocks'.
    """
    img = PIL.Image.open(image_path)
    raw = _get_exif(img)
    report = _init_report(img)
    return _analyze_exif(raw, report)


# ---------------------------------------------------------------------------
# Private helpers for main (in call order)
# ---------------------------------------------------------------------------


def _validate_image_path():
    """Parse CLI arguments and return a validated image file path.

    Returns:
        The image file path from command-line arguments.
    """
    if len(sys.argv) < 2:
        print("Usage: python pixelproof.py <image_path>")
        sys.exit(1)
    image_path = sys.argv[1]
    if not os.path.isfile(image_path):
        print(f"Error: file not found \u2014 {image_path}")
        sys.exit(1)
    return image_path


def _print_header(image_path):
    """Print the PixelProof banner with the target file name.

    Args:
        image_path: Path to the image being analyzed.
    """
    print("=" * 60)
    print("  PIXELPROOF \u2014 Quick Forensic Metadata Scan")
    print(f"  File: {image_path}")
    print("=" * 60)


def _print_file_details(report):
    """Print file detail key-value pairs from the analysis report.

    Args:
        report: Analysis report dictionary containing 'details'.
    """
    print("\n  FILE DETAILS")
    print("  " + "-" * 40)
    for k, v in report["details"].items():
        val = str(v)[:100] + "..." if len(str(v)) > 100 else str(v)
        print(f"    {k}: {val}")


def _print_single_ps_block(block):
    """Print details of a single Photoshop resource block.

    Args:
        block: Dictionary with 'id', 'size', and optional digest/note keys.
    """
    print(f"    ID {block['id']}: {block['size']} bytes")
    if "caption_digest" in block:
        print(f"      Caption Digest: {block['caption_digest']}")
    if "note" in block:
        print(f"      \u26a0 {block['note']}")


def _print_photoshop_blocks(report):
    """Print Photoshop resource block details if present in the report.

    Args:
        report: Analysis report dictionary containing 'photoshop_blocks'.
    """
    if not report["photoshop_blocks"]:
        return
    print("\n  PHOTOSHOP RESOURCE BLOCKS")
    print("  " + "-" * 40)
    for block in report["photoshop_blocks"]:
        _print_single_ps_block(block)


def _print_flags(report):
    """Print forensic flag findings from the analysis report.

    Args:
        report: Analysis report dictionary containing 'flags'.
    """
    if report["flags"]:
        print(f"\n  \u26a0 FLAGS ({len(report['flags'])})")
        print("  " + "-" * 40)
        for f in report["flags"]:
            print(f"    \u2023 {f}")
    else:
        print("\n  \u2713 No red flags found")


def _verdict_line(n_flags):
    """Map forensic flag count to verdict display line.

    Args:
        n_flags: Number of forensic flags.

    Returns:
        Single-line verdict text.
    """
    if n_flags >= 4:
        return "  \U0001f534 HIGHLY SUSPICIOUS"
    if n_flags >= 2:
        return "  \U0001f7e1 SUSPICIOUS"
    return "  \U0001f7e1 MINOR CONCERN" if n_flags == 1 else "  \U0001f7e2 CLEAN"


def _print_verdict(n_flags):
    """Print the final verdict based on the number of forensic flags.

    Args:
        n_flags: Number of forensic flags found.
    """
    verdict = _verdict_line(n_flags)
    print("\n" + "=" * 60)
    print(verdict)
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main():
    """Entry point for the pixelproof quick scan CLI."""
    report = _analyze_metadata(_validate_image_path())
    image_path = sys.argv[1]
    _print_header(image_path)
    _print_file_details(report)
    _print_photoshop_blocks(report)
    _print_flags(report)
    _print_verdict(len(report["flags"]))


if __name__ == "__main__":
    main()
