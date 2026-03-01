#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pixelproof deep -- Full 10-pass forensic analysis with ELA, noise, edge,
color-channel, JPEG compression, and steganography detection checks.

Usage:
    python deep_analysis.py <image_path> [--pdf]

Outputs:
    - Detailed terminal report (ANALYSIS.md quality)
    - <image>_ELA.png   -- Error Level Analysis visualization
    - <image>_REPORT.md -- Markdown forensic report
    - <image>_REPORT.pdf -- PDF report (with --pdf flag)
"""

import sys
import os
import io
import math
import struct
import hashlib
import datetime

import PIL.Image
import PIL.ImageChops
import PIL.ImageEnhance
import PIL.ImageFilter
import PIL.ImageStat
import PIL.ExifTags

from forensic_engine import analyze_advanced_forensics, compute_authenticity_assessment
from provenance import create_provenance_bundle

# ---------------------------------------------------------------------------
# Camera EXIF field names expected in genuine photographs
# ---------------------------------------------------------------------------

CAMERA_FIELDS = [
    "Make",
    "Model",
    "LensModel",
    "FocalLength",
    "FNumber",
    "ExposureTime",
    "ISOSpeedRatings",
    "DateTime",
    "DateTimeOriginal",
]

# ---------------------------------------------------------------------------
# Full set of expected EXIF fields with descriptions of their significance
# ---------------------------------------------------------------------------

ALL_EXPECTED_FIELDS = {
    "Make": "Camera manufacturer (e.g., Apple, Samsung)",
    "Model": "Camera model (e.g., iPhone 15 Pro)",
    "LensModel": "Lens used",
    "FocalLength": "Focal length in mm",
    "FNumber": "Aperture (f-stop)",
    "ExposureTime": "Shutter speed",
    "ISOSpeedRatings": "Sensor sensitivity",
    "Flash": "Whether flash fired",
    "DateTime": "When the photo was taken",
    "DateTimeOriginal": "Original capture timestamp",
    "DateTimeDigitized": "Digitization timestamp",
    "GPSInfo": "Location coordinates",
    "Software": "What software processed it",
}

# ---------------------------------------------------------------------------
# Adobe Photoshop resource block IDs and their human-readable names
# ---------------------------------------------------------------------------

PHOTOSHOP_RESOURCE_NAMES = {
    0x0404: "IPTC-NAA Record",
    0x0425: "Caption Digest",
    0x040C: "Thumbnail Resource",
    0x03ED: "Resolution Info",
    0x03F3: "Print Flags",
    0x0408: "Grid & Guides",
    0x040A: "Copyright Flag",
    0x040B: "URL",
}


# ===========================================================================
# Terminal output helpers
# ===========================================================================


def _section(title):
    """Print a major section header with double-line separators.

    Args:
        title: The section title text to display.
    """
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def _subsection(title):
    """Print a subsection header with dashed separators.

    Args:
        title: The subsection title text to display.
    """
    print(f"\n  --- {title} ---")


# ===========================================================================
# Photoshop 8BIM block parsing helpers
# ===========================================================================


def _parse_dict_ps_blocks(data):
    """Parse Pillow pre-parsed photoshop dict into block list.

    Args:
        data: Dictionary of {resource_id_int: bytes_value}.

    Returns:
        List of block dicts with 'id', 'size', and 'data' keys.
    """
    blocks = []
    for res_id, block_data in data.items():
        blocks.append({"id": res_id, "size": len(block_data), "data": block_data})
    return blocks


def _compute_8bim_data_offset(data, pos):
    """Compute the data offset past the Pascal-string name in an 8BIM block.

    Args:
        data: Raw bytes containing the photoshop data.
        pos: Position of the 8BIM signature.

    Returns:
        Integer offset where the block size field begins.
    """
    name_len = data[pos + 6]
    padded_name_len = name_len + 1 if name_len % 2 == 0 else name_len + 2
    return pos + 6 + padded_name_len


def _extract_raw_8bim_block(data, pos):
    """Extract one 8BIM resource block from raw bytes at a given position.

    Args:
        data: Raw bytes containing photoshop data.
        pos: Position of the 8BIM signature.

    Returns:
        Tuple of (block_dict, next_position) or (None, end_position).
    """
    res_id = struct.unpack(">H", data[pos + 4 : pos + 6])[0]
    data_offset = _compute_8bim_data_offset(data, pos)
    if data_offset + 4 > len(data):
        return None, len(data)
    block_size = struct.unpack(">I", data[data_offset : data_offset + 4])[0]
    block_data = data[data_offset + 4 : data_offset + 4 + block_size]
    next_pos = (
        data_offset
        + 4
        + block_size
        + (1 if (data_offset + 4 + block_size) % 2 != 0 else 0)
    )
    return {"id": res_id, "size": block_size, "data": block_data}, next_pos


def _scan_next_8bim(data, pos):
    """Advance position to the next 8BIM signature in raw bytes.

    Args:
        data: Raw bytes containing photoshop data.
        pos: Starting position to scan from.

    Returns:
        Position of next 8BIM signature, or -1 if not found.
    """
    while pos < len(data) - 12:
        if data[pos : pos + 4] == b"8BIM":
            return pos
        pos += 1
    return -1


def _parse_raw_ps_blocks(data):
    """Parse raw bytes to extract all 8BIM resource blocks.

    Args:
        data: Raw bytes containing photoshop data.

    Returns:
        List of block dicts with 'id', 'size', and 'data' keys.
    """
    blocks = []
    pos = _scan_next_8bim(data, 0)
    while pos >= 0:
        block, pos = _extract_raw_8bim_block(data, pos)
        if block:
            blocks.append(block)
        pos = _scan_next_8bim(data, pos)
    return blocks


def _parse_photoshop_blocks(data):
    """Parse Adobe 8BIM resource blocks from photoshop data.

    Handles both Pillow pre-parsed dict and raw bytes formats.

    Args:
        data: Either a dict {resource_id: bytes} or raw bytes.

    Returns:
        List of block dicts with 'id', 'size', and 'data' keys.
    """
    if isinstance(data, dict):
        return _parse_dict_ps_blocks(data)
    if isinstance(data, bytes):
        return _parse_raw_ps_blocks(data)
    return []


# ===========================================================================
# Pass 1: EXIF Metadata Analysis helpers
# ===========================================================================


def _open_image_for_exif(path):
    """Open an image and extract raw EXIF data and info keys.

    Args:
        path: File path to the image.

    Returns:
        Tuple of (PIL.Image, raw_exif_dict_or_None, info_keys_list).
    """
    img = PIL.Image.open(path)
    raw = img._getexif()
    info_keys = list(img.info.keys())
    return img, raw, info_keys


def _print_image_basics(img, info_keys):
    """Print basic image format, mode, dimensions, and info keys.

    Args:
        img: An opened PIL Image object.
        info_keys: List of keys from img.info.
    """
    print(f"  Format: {img.format}")
    print(f"  Mode: {img.mode}")
    print(f"  Dimensions: {img.size[0]} x {img.size[1]} px")
    print(f"  Info keys: {info_keys}")


def _build_meta_dict(raw):
    """Convert raw EXIF tag IDs to human-readable names.

    Args:
        raw: Dictionary of {tag_id: value} from PIL EXIF data.

    Returns:
        Dictionary of {human_readable_name: value}.
    """
    return {PIL.ExifTags.TAGS.get(t, f"Unknown-{t}"): v for t, v in raw.items()}


def _print_exif_tags(meta):
    """Print all found EXIF tags under the 'What was found' subsection.

    Args:
        meta: Dictionary of human-readable EXIF tag names to values.
    """
    _subsection("What was found")
    print(f"  EXIF tags found: {len(meta)}")
    print("  (A real phone photo typically has 30-80+ tags)\n")
    for k, v in sorted(meta.items()):
        val = str(v)[:120] + "..." if len(str(v)) > 120 else str(v)
        print(f"    {k:25s} : {val}")


def _analyze_and_print_exif(raw):
    """Build EXIF meta dict and print found tags, or print no-data message.

    Args:
        raw: Raw EXIF dictionary from PIL, or None.

    Returns:
        The meta dictionary (empty dict if no EXIF data).
    """
    if not raw:
        print("\n  NO EXIF DATA AT ALL")
        print("  This image contains zero camera metadata tags.")
        return {}
    meta = _build_meta_dict(raw)
    _print_exif_tags(meta)
    return meta


def _print_all_fields_absent_warning():
    """Print warning that all camera hardware fields are absent."""
    print(
        "\n  >> Every single camera hardware field is absent."
        "\n  >> A genuine photo from any phone or camera always writes Make,"
        "\n  >> Model, ISO, shutter speed, and DateTime. Their complete absence"
        "\n  >> means this image was NOT produced by a camera sensor."
    )


def _print_missing_fields(meta):
    """Print critical missing EXIF fields with their significance.

    Args:
        meta: Dictionary of human-readable EXIF tag names to values.
    """
    missing = {k: v for k, v in ALL_EXPECTED_FIELDS.items() if k not in meta}
    if not missing:
        return
    _subsection("What is MISSING (critical)")
    for field, meaning in missing.items():
        print(f"    {field:25s} : {meaning}")
    if len(missing) >= 10:
        _print_all_fields_absent_warning()


def _extract_dpi(meta):
    """Extract DPI value from XResolution EXIF tag.

    Args:
        meta: Dictionary of human-readable EXIF tags.

    Returns:
        Float DPI value, or None if not available.
    """
    if "XResolution" not in meta:
        return None
    xr = meta["XResolution"]
    try:
        return (
            float(xr)
            if not isinstance(xr, tuple)
            else xr[0] / xr[1] if len(xr) == 2 else float(xr)
        )
    except Exception:
        return None


def _print_dpi_warning(meta):
    """Print 72 DPI warning if the image resolution suggests web export.

    Args:
        meta: Dictionary of human-readable EXIF tags.
    """
    dpi_val = _extract_dpi(meta)
    if dpi_val and dpi_val <= 72:
        print(
            f"\n  72 DPI Resolution: Photoshop/web export default."
            f"\n  Camera photos are typically 300 DPI or sensor-native."
        )


def _print_exif_analysis(meta):
    """Print missing fields analysis and DPI warning for EXIF metadata.

    Args:
        meta: Dictionary of human-readable EXIF tags.
    """
    _print_missing_fields(meta)
    _print_dpi_warning(meta)


def _print_photoshop_intro():
    """Print introductory explanation about Photoshop resource blocks."""
    print(
        "  The file headers contain 'photoshop', indicating Adobe 8BIM"
        "\n  resource blocks are embedded. These are Adobe-proprietary binary"
        "\n  markers that only exist in files saved through Photoshop or"
        "\n  compatible software (Lightroom, Bridge, etc.)."
    )
    print(
        "\n  A photo taken directly by a phone/camera and never opened in"
        "\n  Photoshop will NEVER contain 8BIM resource blocks."
    )


def _format_ps_block_base(block):
    """Format the basic display columns for a Photoshop resource block.

    Args:
        block: Block dict with 'id' and 'size' keys.

    Returns:
        Tuple of (resource_id_str, resource_name_str, size_str).
    """
    rid = f"0x{block['id']:04X} ({block['id']})"
    rname = PHOTOSHOP_RESOURCE_NAMES.get(block["id"], "Unknown")
    rsize = f"{block['size']} bytes"
    return rid, rname, rsize


def _print_caption_digest_block(rid, rname, rsize, block):
    """Print a caption digest (0x0425) block with MD5 analysis.

    Args:
        rid: Formatted resource ID string.
        rname: Resource name string.
        rsize: Formatted size string.
        block: Block dict with 'data' key.
    """
    digest_hex = block["data"].hex()
    print(f"    {rid:20s} {rname:20s} {rsize:10s} {digest_hex}")
    md5_empty = hashlib.md5(b"").hexdigest()
    if digest_hex == md5_empty:
        print(
            f"\n  >> Caption Digest = {digest_hex}"
            f"\n  >> This is the MD5 hash of an EMPTY STRING."
            f"\n  >> The caption/description was deliberately blanked"
            f"\n  >> out before saving -- consistent with scrubbing"
            f"\n  >> identifying information from a manipulated image."
        )


def _print_iptc_block(rid, rname, rsize, block):
    """Print an IPTC-NAA (0x0404) Photoshop block row.

    Args:
        rid: Formatted resource ID string.
        rname: Resource name string.
        rsize: Formatted size string.
        block: Block dict with 'size' key.
    """
    suffix = (
        " Empty (IPTC deliberately cleared)"
        if block["size"] == 0
        else " IPTC data present"
    )
    print(f"    {rid:20s} {rname:20s} {rsize:10s}{suffix}")


def _print_exif_ps_block(block):
    """Print one Photoshop resource block row with type-specific handling.

    Args:
        block: Block dict with 'id', 'size', and 'data' keys.
    """
    rid, rname, rsize = _format_ps_block_base(block)
    if block["id"] == 0x0425 and block["size"] == 16:
        _print_caption_digest_block(rid, rname, rsize, block)
    elif block["id"] == 0x0404:
        _print_iptc_block(rid, rname, rsize, block)
    else:
        print(f"    {rid:20s} {rname:20s} {rsize:10s}")


def _print_ps_block_header(count):
    """Print the table header for Photoshop resource blocks.

    Args:
        count: Number of blocks found.
    """
    print(f"\n  Found {count} Adobe 8BIM resource block(s):\n")
    print(f"    {'Resource ID':20s} {'Name':20s} {'Size':10s} Contents")
    print(f"    {'-' * 20} {'-' * 20} {'-' * 10} {'-' * 30}")


def _print_ps_blocks_if_present(ps_blocks):
    """Print the Photoshop block table header and all rows if blocks exist.

    Args:
        ps_blocks: List of parsed photoshop block dicts.
    """
    if not ps_blocks:
        return
    _print_ps_block_header(len(ps_blocks))
    for block in ps_blocks:
        _print_exif_ps_block(block)


def _analyze_photoshop_data(img):
    """Analyze and print Photoshop resource block data from image headers.

    Args:
        img: An opened PIL Image object.

    Returns:
        List of parsed photoshop block dicts, or empty list.
    """
    photoshop_data = img.info.get("photoshop")
    if not photoshop_data:
        return []
    _subsection("Photoshop Resource Block Detected")
    _print_photoshop_intro()
    ps_blocks = _parse_photoshop_blocks(photoshop_data)
    _print_ps_blocks_if_present(ps_blocks)
    return ps_blocks


def _format_info_value(val):
    """Format an info key value for display, truncating bytes and long strings.

    Args:
        val: The value to format.

    Returns:
        Formatted string representation, truncated if needed.
    """
    val_str = str(val)
    if len(val_str) > 80:
        return f"<{len(val)} bytes>" if isinstance(val, bytes) else val_str[:80] + "..."
    return val_str


def _print_info_keys_table(img, info_keys):
    """Print all file header info keys in a formatted table.

    Args:
        img: An opened PIL Image object.
        info_keys: List of info key names.
    """
    if not info_keys:
        return
    _subsection("All file header info keys")
    for key in sorted(info_keys):
        print(f"    {key:20s} : {_format_info_value(img.info[key])}")


def _finalize_exif_dump(img, info_keys, meta, ps_blocks):
    """Print info keys, close image, and return EXIF analysis results.

    Args:
        img: An opened PIL Image object.
        info_keys: List of info key names.
        meta: Parsed EXIF metadata dictionary.
        ps_blocks: List of parsed photoshop block dicts.

    Returns:
        Tuple of (meta, info_keys, ps_blocks).
    """
    _print_info_keys_table(img, info_keys)
    img.close()
    return meta, info_keys, ps_blocks


def _full_exif_dump(path):
    """Run comprehensive EXIF metadata analysis with terminal output.

    Args:
        path: File path to the image.

    Returns:
        Tuple of (meta_dict, info_keys_list, photoshop_blocks_list).
    """
    _section("1. EXIF METADATA ANALYSIS")
    img, raw, info_keys = _open_image_for_exif(path)
    _print_image_basics(img, info_keys)
    meta = _analyze_and_print_exif(raw)
    _print_exif_analysis(meta)
    ps_blocks = _analyze_photoshop_data(img)
    return _finalize_exif_dump(img, info_keys, meta, ps_blocks)


# ===========================================================================
# Pass 2: Grid-Based Error Level Analysis helpers
# ===========================================================================


def _compute_ela_diff(original_path):
    """Open image, resave at JPEG quality 90, and compute pixel difference.

    Args:
        original_path: Path to the original image file.

    Returns:
        Tuple of (difference_image, width, height).
    """
    original = PIL.Image.open(original_path).convert("RGB")
    w, h = original.size
    buf = io.BytesIO()
    original.save(buf, "JPEG", quality=90)
    buf.seek(0)
    resaved = PIL.Image.open(buf).convert("RGB")
    diff = PIL.ImageChops.difference(original, resaved)
    return diff, w, h


def _print_grid_header(grid_size, cell_w, cell_h):
    """Print the ELA grid header with column labels.

    Args:
        grid_size: Number of grid divisions per axis.
        cell_w: Width of each grid cell in pixels.
        cell_h: Height of each grid cell in pixels.
    """
    print(f"\n  Grid: {grid_size}x{grid_size} cells, each {cell_w}x{cell_h} px\n")
    header = "          " + "".join(f"  Col{c:<3}" for c in range(grid_size))
    print(header)
    print("         " + "-" * (grid_size * 8))


def _compute_grid_cell(diff, row, col, cell_w, cell_h):
    """Compute ELA statistics for a single grid cell.

    Args:
        diff: The ELA difference image.
        row: Grid row index.
        col: Grid column index.
        cell_w: Width of each cell in pixels.
        cell_h: Height of each cell in pixels.

    Returns:
        Dictionary with cell coordinates, mean_error, and max_per_channel.
    """
    x1, y1 = col * cell_w, row * cell_h
    x2, y2 = x1 + cell_w, y1 + cell_h
    cell = diff.crop((x1, y1, x2, y2))
    stat = PIL.ImageStat.Stat(cell)
    mean = sum(stat.mean) / 3
    return {
        "row": row,
        "col": col,
        "x1": x1,
        "y1": y1,
        "x2": x2,
        "y2": y2,
        "mean_error": round(mean, 2),
        "max_per_channel": [int(e[1]) for e in cell.getextrema()],
    }


def _process_grid_row(diff, row, grid_size, cell_w, cell_h, global_means, grid_data):
    """Process one grid row: compute cells, print means, accumulate data.

    Args:
        diff: The ELA difference image.
        row: Grid row index.
        grid_size: Number of columns.
        cell_w: Cell width in pixels.
        cell_h: Cell height in pixels.
        global_means: List to append mean values to.
        grid_data: List to append cell data dicts to.
    """
    row_str = f"  Row {row} |"
    for col in range(grid_size):
        cell_data = _compute_grid_cell(diff, row, col, cell_w, cell_h)
        global_means.append(cell_data["mean_error"])
        grid_data.append(cell_data)
        row_str += f"  {cell_data['mean_error']:5.2f} "
    print(row_str)


def _compute_grid_stats(global_means):
    """Compute overall mean, standard deviation, and hotspot threshold.

    Args:
        global_means: List of mean error values from all grid cells.

    Returns:
        Tuple of (overall_mean, overall_std, threshold).
    """
    overall_mean = sum(global_means) / len(global_means)
    overall_std = math.sqrt(
        sum((m - overall_mean) ** 2 for m in global_means) / len(global_means)
    )
    threshold = overall_mean + 2 * overall_std
    return overall_mean, overall_std, threshold


def _print_grid_stats(overall_mean, overall_std, threshold):
    """Print the overall grid ELA statistics.

    Args:
        overall_mean: Mean of all cell mean errors.
        overall_std: Standard deviation of cell mean errors.
        threshold: Hotspot detection threshold (mean + 2*std).
    """
    print(f"\n  Overall mean error: {overall_mean:.2f}")
    print(f"  Std deviation:      {overall_std:.2f}")
    print(f"  Hotspot threshold (mean + 2s): {threshold:.2f}")


def _get_cell_location(row, col, grid_size):
    """Determine human-readable location label for a grid cell.

    Args:
        row: Grid row index.
        col: Grid column index.
        grid_size: Total grid divisions per axis.

    Returns:
        Location string like 'top-left' or 'middle-center'.
    """
    col_pos = (
        "left"
        if col < grid_size // 3
        else ("center" if col < 2 * grid_size // 3 else "right")
    )
    row_pos = (
        "top"
        if row < grid_size // 3
        else ("middle" if row < 2 * grid_size // 3 else "bottom")
    )
    return f"{row_pos}-{col_pos}"


def _print_hotspot_row(cell, grid_size):
    """Print a single hotspot cell row in the detection table.

    Args:
        cell: Cell data dictionary with coordinates and error values.
        grid_size: Total grid divisions per axis.
    """
    loc = _get_cell_location(cell["row"], cell["col"], grid_size)
    gc = f"Row {cell['row']}, Col {cell['col']}"
    region = f"({cell['x1']},{cell['y1']})-({cell['x2']},{cell['y2']})"
    chans = f"R={cell['max_per_channel'][0]}, G={cell['max_per_channel'][1]}, B={cell['max_per_channel'][2]}"
    print(f"    {loc:20s} {gc:15s} {region:25s} {cell['mean_error']:<12.2f} {chans}")


def _print_hotspot_header():
    """Print the column headers for the hotspot detection table."""
    print(
        f"\n    {'Location':20s} {'Grid Cell':15s}"
        f" {'Pixel Region':25s} {'Mean Error':12s} {'Max Ch Errors':15s}"
    )
    print(f"    {'-' * 20} {'-' * 15} {'-' * 25} {'-' * 12} {'-' * 15}")


def _print_hotspot_conclusion():
    """Print interpretive text about detected hotspot regions."""
    print(
        "\n  These regions compress differently from the rest of the"
        "\n  image, which is consistent with content being pasted,"
        "\n  cloned, or digitally altered in those areas."
    )


def _print_hotspots(grid_data, threshold, grid_size):
    """Detect and print hotspot cells that exceed the error threshold.

    Args:
        grid_data: List of cell data dicts from the grid analysis.
        threshold: Mean error threshold for hotspot detection.
        grid_size: Total grid divisions per axis.

    Returns:
        List of hotspot cell data dicts.
    """
    hotspots = [c for c in grid_data if c["mean_error"] > threshold]
    if not hotspots:
        print("\n  No hotspot cells detected above threshold.")
        return hotspots
    _subsection("Hotspot Cells Detected")
    _print_hotspot_header()
    for cell in hotspots:
        _print_hotspot_row(cell, grid_size)
    _print_hotspot_conclusion()
    return hotspots


def _grid_ela_analysis(original_path, grid_size=8):
    """Run grid-based Error Level Analysis on an image.

    Args:
        original_path: Path to the image file.
        grid_size: Number of grid divisions per axis (default 8).

    Returns:
        Tuple of (grid_data, hotspots, overall_mean, overall_std, threshold).
    """
    _section("2. GRID-BASED ERROR LEVEL ANALYSIS")
    print(
        "\n  ELA resaves the image at a known JPEG quality and computes the"
        "\n  pixel-by-pixel difference. In an unedited photo, error levels are"
        "\n  uniform. Edited regions compress differently and show as bright"
        "\n  spots."
    )
    diff, w, h = _compute_ela_diff(original_path)
    cell_w, cell_h = w // grid_size, h // grid_size
    _print_grid_header(grid_size, cell_w, cell_h)
    global_means, grid_data = [], []
    for row in range(grid_size):
        _process_grid_row(diff, row, grid_size, cell_w, cell_h, global_means, grid_data)
    overall_mean, overall_std, threshold = _compute_grid_stats(global_means)
    _print_grid_stats(overall_mean, overall_std, threshold)
    hotspots = _print_hotspots(grid_data, threshold, grid_size)
    return grid_data, hotspots, overall_mean, overall_std, threshold


# ===========================================================================
# Pass 3: ELA Image + Brightness Distribution helpers
# ===========================================================================


def _create_ela_diff(image_path, quality):
    """Create an ELA difference image by resaving at a given JPEG quality.

    Args:
        image_path: Path to the original image.
        quality: JPEG quality level for resaving.

    Returns:
        Tuple of (original_image, difference_image).
    """
    original = PIL.Image.open(image_path).convert("RGB")
    buf = io.BytesIO()
    original.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    resaved = PIL.Image.open(buf).convert("RGB")
    diff = PIL.ImageChops.difference(original, resaved)
    return original, diff


def _save_ela_image(diff, image_path, scale):
    """Scale and save the ELA difference image as a PNG.

    Args:
        diff: The ELA difference image.
        image_path: Original image path (used to derive output path).
        scale: Brightness enhancement factor.

    Returns:
        Tuple of (ela_output_path, scaled_diff_image).
    """
    diff_scaled = PIL.ImageEnhance.Brightness(diff).enhance(scale)
    ela_path = os.path.splitext(image_path)[0] + "_ELA.png"
    diff_scaled.save(ela_path)
    return ela_path, diff_scaled


def _build_ela_result(ela_path, diff):
    """Build the ELA result dictionary from the difference image.

    Args:
        ela_path: Path where the ELA image was saved.
        diff: The unscaled ELA difference image.

    Returns:
        Dictionary with ELA statistics and file path.
    """
    extrema = diff.getextrema()
    stat = PIL.ImageStat.Stat(diff)
    return {
        "ela_image_saved": ela_path,
        "channel_extrema_rgb": extrema,
        "mean_error_rgb": tuple(round(m, 2) for m in stat.mean),
        "stddev_rgb": tuple(round(s, 2) for s in stat.stddev),
        "max_error": max(e[1] for e in extrema),
    }


def _print_ela_summary(result):
    """Print the ELA image summary statistics with interpretation.

    Args:
        result: ELA result dictionary.
    """
    print(f"  ELA image saved: {result['ela_image_saved']}")
    print(f"  Mean error (R,G,B):  {result['mean_error_rgb']}")
    print(f"  Std-dev (R,G,B):     {result['stddev_rgb']}")
    print(f"  Max pixel error:     {result['max_error']}")
    if result["max_error"] > 40:
        print("\n  >> HIGH ERROR REGIONS -- suggests edits or compositing")
    elif result["max_error"] > 25:
        print("\n  >> MODERATE ERROR VARIATION -- some regions may be altered")
    else:
        print("\n  Error levels appear relatively uniform.")


def _compute_brightness_ranges():
    """Return the standard brightness range definitions for ELA analysis.

    Returns:
        List of (label, low_inclusive, high_exclusive) tuples.
    """
    return [
        ("Black (0-10)", 0, 11),
        ("Very dark (11-30)", 11, 31),
        ("Dark (31-60)", 31, 61),
        ("Medium (61-120)", 61, 121),
        ("Bright (121-180)", 121, 181),
        ("Very bright (181-240)", 181, 241),
        ("Near-white (241-255)", 241, 256),
    ]


def _compute_brightness_dist(diff_scaled):
    """Compute the ELA brightness distribution across standard ranges.

    Args:
        diff_scaled: The brightness-enhanced ELA difference image.

    Returns:
        Dictionary of {range_label: percentage}.
    """
    gray = diff_scaled.convert("L")
    total_px = gray.size[0] * gray.size[1]
    hist = gray.histogram()
    brightness_dist = {}
    for label, lo, hi in _compute_brightness_ranges():
        brightness_dist[label] = 100.0 * sum(hist[lo:hi]) / total_px
    return brightness_dist


def _print_brightness_dist(brightness_dist):
    """Print the ELA brightness distribution table.

    Args:
        brightness_dist: Dictionary of {range_label: percentage}.
    """
    _subsection("ELA Brightness Distribution")
    print()
    for label, pct in brightness_dist.items():
        pct_str = f"{pct:.2f}%" if pct >= 0.01 else "<0.01%"
        print(f"    {label:25s} : {pct_str}")


def _perform_ela(image_path, quality=90, scale=15):
    """Run Error Level Analysis and produce the ELA image with statistics.

    Args:
        image_path: Path to the image file.
        quality: JPEG quality for resaving (default 90).
        scale: Brightness enhancement factor (default 15).

    Returns:
        Dictionary with ELA statistics, file path, and brightness distribution.
    """
    _section("3. ERROR LEVEL ANALYSIS (ELA) IMAGE")
    original, diff = _create_ela_diff(image_path, quality)
    ela_path, diff_scaled = _save_ela_image(diff, image_path, scale)
    result = _build_ela_result(ela_path, diff)
    _print_ela_summary(result)
    result["brightness_dist"] = _compute_brightness_dist(diff_scaled)
    _print_brightness_dist(result["brightness_dist"])
    return result


# ===========================================================================
# Pass 4: Multi-Quality ELA Comparison helpers
# ===========================================================================


def _print_mq_header():
    """Print the multi-quality ELA comparison table header."""
    print(
        "\n  By resaving at multiple JPEG quality levels, we can estimate"
        "\n  the quality the image was originally saved at. The quality"
        "\n  level with the lowest mean error is closest to the original.\n"
    )
    print(f"    {'Quality':8s} {'Mean Error (R,G,B)':32s} {'Max Error':10s} Notes")
    print(f"    {'-' * 8} {'-' * 32} {'-' * 10} {'-' * 30}")


def _compute_single_quality(original, q):
    """Compute ELA statistics for a single JPEG quality level.

    Args:
        original: The original PIL Image (RGB mode).
        q: JPEG quality level to test.

    Returns:
        Dictionary with quality, mean_rgb, and max_error.
    """
    buf = io.BytesIO()
    original.save(buf, "JPEG", quality=q)
    buf.seek(0)
    resaved = PIL.Image.open(buf).convert("RGB")
    diff = PIL.ImageChops.difference(original, resaved)
    stat = PIL.ImageStat.Stat(diff)
    max_err = max(e[1] for e in diff.getextrema())
    mean_rgb = tuple(round(m, 2) for m in stat.mean)
    return {"quality": q, "mean_rgb": mean_rgb, "max_error": max_err}


def _print_mq_row(r):
    """Print a single row of the multi-quality ELA comparison table.

    Args:
        r: Result dictionary with quality, mean_rgb, and max_error.
    """
    avg = sum(r["mean_rgb"]) / 3
    note = ""
    if r["quality"] >= 85 and avg < 1.0:
        note = "Very low -- may match original quality"
    elif r["quality"] >= 85 and avg < 2.0:
        note = "Low error"
    print(
        f"    {r['quality']:5d}    {str(r['mean_rgb']):32s} {r['max_error']:5d}     {note}"
    )


def _print_mq_conclusion(best):
    """Print the estimated original JPEG quality conclusion.

    Args:
        best: Result dict for the quality level with lowest mean error.
    """
    print(f"\n  Estimated original JPEG quality: ~{best['quality']}")
    if best["quality"] >= 95:
        print(
            "  This is consistent with Photoshop 'Maximum' quality export,"
            "\n  not a typical phone camera JPEG (usually 80-92)."
        )


def _multi_quality_ela(original_path):
    """Compare ELA at multiple JPEG quality levels to estimate original quality.

    Args:
        original_path: Path to the image file.

    Returns:
        Tuple of (results_list, best_quality_dict).
    """
    _section("4. MULTI-QUALITY ELA COMPARISON")
    _print_mq_header()
    original = PIL.Image.open(original_path).convert("RGB")
    results = []
    for q in [50, 60, 70, 75, 80, 85, 90, 95, 98]:
        r = _compute_single_quality(original, q)
        results.append(r)
        _print_mq_row(r)
    best = min(results, key=lambda r: sum(r["mean_rgb"]))
    _print_mq_conclusion(best)
    return results, best


# ===========================================================================
# Pass 5: Image Statistics helpers
# ===========================================================================


def _compute_image_metrics(image_path):
    """Compute basic image metrics including dimensions, file size, and BPP.

    Args:
        image_path: Path to the image file.

    Returns:
        Tuple of (width, height, aspect_ratio, file_size, bpp, PIL_stat).
    """
    img = PIL.Image.open(image_path).convert("RGB")
    stat = PIL.ImageStat.Stat(img)
    w, h = img.size
    file_size = os.path.getsize(image_path)
    bpp = (file_size * 8) / (w * h)
    return w, h, w / h, file_size, bpp, stat


def _build_stats_report(w, h, ratio, file_size, bpp, stat):
    """Build the image statistics report dictionary.

    Args:
        w: Image width in pixels.
        h: Image height in pixels.
        ratio: Aspect ratio (w/h).
        file_size: File size in bytes.
        bpp: Bits per pixel.
        stat: PIL ImageStat object.

    Returns:
        Report dictionary with all metrics and an empty flags list.
    """
    return {
        "dimensions": f"{w} x {h}",
        "aspect_ratio": round(ratio, 3),
        "mean_rgb": tuple(round(m, 1) for m in stat.mean),
        "stddev_rgb": tuple(round(s, 1) for s in stat.stddev),
        "file_size_kb": round(file_size / 1024, 1),
        "bits_per_pixel": round(bpp, 2),
        "flags": [],
    }


def _print_stats_table(w, h, ratio, bpp, report):
    """Print the image statistics metrics table.

    Args:
        w: Image width.
        h: Image height.
        ratio: Aspect ratio.
        bpp: Bits per pixel.
        report: Stats report dictionary.
    """
    print(f"\n    {'Metric':20s} Value")
    print(f"    {'-' * 20} {'-' * 30}")
    print(f"    {'Dimensions':20s} {w} x {h}")
    print(f"    {'Aspect ratio':20s} {ratio:.3f}")
    print(f"    {'File size':20s} {report['file_size_kb']} KB")
    print(f"    {'Bits per pixel':20s} {bpp:.2f}")
    print(f"    {'Mean RGB':20s} {report['mean_rgb']}")
    print(f"    {'Std dev RGB':20s} {report['stddev_rgb']}")


def _check_stats_flags(w, h, bpp, stat):
    """Check image statistics for forensic red flags.

    Args:
        w: Image width in pixels.
        h: Image height in pixels.
        bpp: Bits per pixel.
        stat: PIL ImageStat object.

    Returns:
        List of flag description strings.
    """
    flags = []
    if max(stat.stddev) - min(stat.stddev) < 2.0:
        flags.append("SUSPICIOUSLY UNIFORM CHANNEL VARIANCE -- possible AI-generated")
    if bpp < 0.5:
        flags.append(f"VERY LOW QUALITY -- {bpp:.2f} bpp suggests heavy compression")
    elif bpp < 1.5:
        flags.append(f"LOW-MODERATE QUALITY -- {bpp:.2f} bpp")
    if w % 64 == 0 and h % 64 == 0:
        flags.append(f"DIMENSIONS DIVISIBLE BY 64 ({w}x{h}) -- common in AI images")
    return flags


def _print_stats_flags(flags):
    """Print image statistics flags or a normal-status message.

    Args:
        flags: List of flag description strings.
    """
    if flags:
        print("\n  Flags:")
        for f in flags:
            print(f"    >> {f}")
    else:
        print("\n  Statistics appear normal.")


def _analyze_image_stats(image_path):
    """Analyze image statistics and check for forensic red flags.

    Args:
        image_path: Path to the image file.

    Returns:
        Report dictionary with metrics and flags.
    """
    _section("5. IMAGE STATISTICS")
    w, h, ratio, file_size, bpp, stat = _compute_image_metrics(image_path)
    report = _build_stats_report(w, h, ratio, file_size, bpp, stat)
    _print_stats_table(w, h, ratio, bpp, report)
    report["flags"] = _check_stats_flags(w, h, bpp, stat)
    _print_stats_flags(report["flags"])
    return report


# ===========================================================================
# Pass 6: Edge & Boundary Analysis helpers
# ===========================================================================


def _compute_edges(original_path):
    """Compute edge detection on a grayscale version of the image.

    Args:
        original_path: Path to the image file.

    Returns:
        Tuple of (edges_image, edge_mean, edge_std).
    """
    img = PIL.Image.open(original_path).convert("L")
    edges = img.filter(PIL.ImageFilter.FIND_EDGES)
    stat = PIL.ImageStat.Stat(edges)
    return edges, stat.mean[0], stat.stddev[0]


def _print_edge_summary(edge_mean, edge_std):
    """Print overall edge detection statistics.

    Args:
        edge_mean: Mean edge intensity value.
        edge_std: Standard deviation of edge intensity.
    """
    print(f"\n  Mean edge intensity: {edge_mean:.2f}")
    print(f"  Std dev:             {edge_std:.2f}")


def _compute_quadrant_edges(edges):
    """Compute mean edge intensity for each image quadrant.

    Args:
        edges: The edge-detected grayscale image.

    Returns:
        Dictionary of {quadrant_name: mean_edge_intensity}.
    """
    w, h = edges.size
    quadrants = {
        "top-left": edges.crop((0, 0, w // 2, h // 2)),
        "top-right": edges.crop((w // 2, 0, w, h // 2)),
        "bottom-left": edges.crop((0, h // 2, w // 2, h)),
        "bottom-right": edges.crop((w // 2, h // 2, w, h)),
    }
    return {name: PIL.ImageStat.Stat(quad).mean[0] for name, quad in quadrants.items()}


def _print_quadrant_table(edges, quad_means):
    """Print the quadrant edge intensity comparison table.

    Args:
        edges: The edge-detected image (for computing stddev per quad).
        quad_means: Dictionary of {quadrant_name: mean_edge_intensity}.
    """
    w, h = edges.size
    quadrants = {
        "top-left": edges.crop((0, 0, w // 2, h // 2)),
        "top-right": edges.crop((w // 2, 0, w, h // 2)),
        "bottom-left": edges.crop((0, h // 2, w // 2, h)),
        "bottom-right": edges.crop((w // 2, h // 2, w, h)),
    }
    print(f"\n    {'Quadrant':15s} {'Mean':10s} {'Std Dev':10s}")
    print(f"    {'-' * 15} {'-' * 10} {'-' * 10}")
    for name, quad in quadrants.items():
        qstat = PIL.ImageStat.Stat(quad)
        print(f"    {name:15s} {qstat.mean[0]:10.2f} {qstat.stddev[0]:10.2f}")


def _print_edge_conclusion(quad_means):
    """Print interpretive conclusion about edge density balance.

    Args:
        quad_means: Dictionary of {quadrant_name: mean_edge_intensity}.
    """
    vals = list(quad_means.values())
    if max(vals) > 2 * min(vals) and min(vals) > 1:
        print(
            "\n  >> EDGE DENSITY IMBALANCE -- one region has significantly"
            "\n  >> different edge characteristics, suggesting composited"
            "\n  >> elements."
        )
    else:
        print(
            "\n  Edge density is relatively balanced across quadrants."
            "\n  No obvious compositing seams detected."
        )


def _edge_analysis(original_path):
    """Analyze edge density distribution across image quadrants.

    Args:
        original_path: Path to the image file.

    Returns:
        Tuple of (quad_means_dict, edge_mean, edge_std).
    """
    _section("6. EDGE & BOUNDARY ANALYSIS")
    print(
        "\n  Edge detection looks for unnatural boundaries that could"
        "\n  indicate composited elements pasted onto the image."
    )
    edges, edge_mean, edge_std = _compute_edges(original_path)
    _print_edge_summary(edge_mean, edge_std)
    quad_means = _compute_quadrant_edges(edges)
    _print_quadrant_table(edges, quad_means)
    _print_edge_conclusion(quad_means)
    return quad_means, edge_mean, edge_std


# ===========================================================================
# Pass 7: Color Channel Correlation helpers
# ===========================================================================


def _sample_channel_data(img):
    """Split image into RGB channels and sample pixel data.

    Args:
        img: A PIL Image in RGB mode.

    Returns:
        Tuple of (r_data, g_data, b_data, sample_count).
    """
    r, g, b = img.split()
    w, h = img.size
    step = max(1, (w * h) // min(50000, w * h))
    r_data = list(r.get_flattened_data())[::step]
    g_data = list(g.get_flattened_data())[::step]
    b_data = list(b.get_flattened_data())[::step]
    return r_data, g_data, b_data, len(r_data)


def _pearson(x, y, n):
    """Compute Pearson correlation coefficient between two data sequences.

    Args:
        x: First sequence of numeric values.
        y: Second sequence of numeric values.
        n: Number of data points.

    Returns:
        Pearson correlation coefficient as a float.
    """
    mx, my = sum(x) / n, sum(y) / n
    num = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
    dx = math.sqrt(sum((xi - mx) ** 2 for xi in x))
    dy = math.sqrt(sum((yi - my) ** 2 for yi in y))
    return num / (dx * dy) if dx * dy else 0


def _compute_correlations(r_data, g_data, b_data, n):
    """Compute pairwise Pearson correlations between RGB channels.

    Args:
        r_data: Red channel sample data.
        g_data: Green channel sample data.
        b_data: Blue channel sample data.
        n: Number of sample points.

    Returns:
        Tuple of (rg_correlation, rb_correlation, gb_correlation).
    """
    rg = _pearson(r_data, g_data, n)
    rb = _pearson(r_data, b_data, n)
    gb = _pearson(g_data, b_data, n)
    return rg, rb, gb


def _print_correlation_table(rg, rb, gb):
    """Print the RGB channel correlation table.

    Args:
        rg: Red-Green Pearson correlation.
        rb: Red-Blue Pearson correlation.
        gb: Green-Blue Pearson correlation.
    """
    print(f"\n    {'Channel Pair':15s} {'Pearson r':12s}")
    print(f"    {'-' * 15} {'-' * 12}")
    print(f"    {'R-G':15s} {rg:.4f}")
    print(f"    {'R-B':15s} {rb:.4f}")
    print(f"    {'G-B':15s} {gb:.4f}")


def _print_correlation_conclusion(min_corr):
    """Print interpretive conclusion about channel correlation strength.

    Args:
        min_corr: Minimum correlation value among all channel pairs.
    """
    if min_corr < 0.5:
        print(f"\n  >> LOW CORRELATION ({min_corr:.2f}) -- unusual for natural photos")
    elif min_corr < 0.75:
        print(f"\n  >> MODERATE CORRELATION ({min_corr:.2f}) -- possible processing")
    else:
        print(
            f"\n  All correlations above {min_corr:.2f} -- falls in the"
            f" normal range for a natural-looking photograph."
        )


def _channel_correlation(original_path):
    """Analyze pairwise correlation between RGB color channels.

    Args:
        original_path: Path to the image file.

    Returns:
        Dictionary with 'rg', 'rb', and 'gb' correlation values.
    """
    _section("7. COLOR CHANNEL CORRELATION")
    print(
        "\n  Natural photographs have high correlation between R, G, and B"
        "\n  channels because real-world lighting affects all channels"
        "\n  similarly. AI-generated or heavily composited images can show"
        "\n  lower correlation."
    )
    img = PIL.Image.open(original_path).convert("RGB")
    r_data, g_data, b_data, n = _sample_channel_data(img)
    rg, rb, gb = _compute_correlations(r_data, g_data, b_data, n)
    _print_correlation_table(rg, rb, gb)
    _print_correlation_conclusion(min(rg, rb, gb))
    return {"rg": round(rg, 4), "rb": round(rb, 4), "gb": round(gb, 4)}


# ===========================================================================
# Pass 8: Noise Analysis helpers
# ===========================================================================


def _compute_noise_image(original_path):
    """Compute a noise residual image by subtracting a Gaussian blur.

    Args:
        original_path: Path to the image file.

    Returns:
        Tuple of (noise_image, width, height).
    """
    img = PIL.Image.open(original_path).convert("L")
    w, h = img.size
    blurred = img.filter(PIL.ImageFilter.GaussianBlur(radius=2))
    noise = PIL.ImageChops.difference(img, blurred)
    return noise, w, h


def _compute_noise_grid(noise, w, h, grid):
    """Compute mean noise level for each cell in a grid.

    Args:
        noise: The noise residual image.
        w: Image width.
        h: Image height.
        grid: Number of grid divisions per axis.

    Returns:
        Dictionary of {(row, col): mean_noise_level}.
    """
    cell_w, cell_h = w // grid, h // grid
    noise_vals = {}
    for row in range(grid):
        for col in range(grid):
            x1, y1 = col * cell_w, row * cell_h
            cell = noise.crop((x1, y1, x1 + cell_w, y1 + cell_h))
            noise_vals[(row, col)] = PIL.ImageStat.Stat(cell).mean[0]
    return noise_vals


def _print_noise_grid(noise_vals, grid):
    """Print the noise level grid values.

    Args:
        noise_vals: Dictionary of {(row, col): mean_noise_level}.
        grid: Number of grid divisions per axis.
    """
    _subsection(f"Noise Levels by Region ({grid}x{grid} grid)")
    print()
    for row in range(grid):
        line = "    "
        for col in range(grid):
            line += f"  {noise_vals[(row, col)]:5.2f}"
        print(line)


def _compute_noise_stats(noise_vals):
    """Compute aggregate noise statistics from grid measurements.

    Args:
        noise_vals: Dictionary of {(row, col): mean_noise_level}.

    Returns:
        Tuple of (mean_noise, std_noise, coefficient_of_variation).
    """
    vals = list(noise_vals.values())
    mean_n = sum(vals) / len(vals)
    std_n = math.sqrt(sum((v - mean_n) ** 2 for v in vals) / len(vals))
    cv = std_n / mean_n if mean_n > 0 else 0
    return mean_n, std_n, cv


def _print_noise_stats(mean_n, std_n, cv):
    """Print aggregate noise statistics table.

    Args:
        mean_n: Mean noise level across all grid cells.
        std_n: Standard deviation of noise levels.
        cv: Coefficient of variation.
    """
    print(f"\n    {'Metric':30s} Value")
    print(f"    {'-' * 30} {'-' * 10}")
    print(f"    {'Mean noise level':30s} {mean_n:.2f}")
    print(f"    {'Noise standard deviation':30s} {std_n:.2f}")
    print(f"    {'Coefficient of variation':30s} {cv:.3f}")


def _print_noise_conclusion(noise_vals, cv):
    """Print interpretive conclusion about noise consistency.

    Args:
        noise_vals: Dictionary of {(row, col): mean_noise_level}.
        cv: Coefficient of variation.
    """
    vals = list(noise_vals.values())
    min_noise, max_noise = min(vals), max(vals)
    ratio = max_noise / min_noise if min_noise > 0 else 0
    if cv > 0.3:
        print(
            f"\n  >> HIGHLY INCONSISTENT NOISE (CV={cv:.2f})"
            f"\n  >> Lowest region ({min_noise:.2f}) vs highest ({max_noise:.2f})"
            f"\n  >> is a {ratio:.1f}x difference. In a genuine single-exposure photo,"
            f"\n  >> noise should be much more uniform. This variation is"
            f"\n  >> consistent with different parts originating from different sources."
        )
    elif cv > 0.2:
        print(
            f"\n  >> MODERATELY INCONSISTENT NOISE (CV={cv:.2f})"
            f"\n  >> Lowest ({min_noise:.2f}) vs highest ({max_noise:.2f}) = {ratio:.1f}x difference."
        )
    else:
        print(f"\n  Noise is consistent (CV={cv:.2f}).")


def _noise_analysis(original_path):
    """Analyze noise consistency across image regions.

    Args:
        original_path: Path to the image file.

    Returns:
        Tuple of (noise_vals_dict, mean_noise, std_noise, cv).
    """
    _section("8. NOISE ANALYSIS")
    print(
        "\n  Genuine photographs have consistent noise from the camera"
        "\n  sensor across the entire image. When regions are pasted,"
        "\n  cloned, or generated separately, they carry different noise"
        "\n  signatures."
    )
    noise, w, h = _compute_noise_image(original_path)
    noise_vals = _compute_noise_grid(noise, w, h, 4)
    _print_noise_grid(noise_vals, 4)
    mean_n, std_n, cv = _compute_noise_stats(noise_vals)
    _print_noise_stats(mean_n, std_n, cv)
    _print_noise_conclusion(noise_vals, cv)
    return noise_vals, mean_n, std_n, cv


# ===========================================================================
# Pass 9: JPEG Compression Analysis helpers
# ===========================================================================


def _analyze_qtable(idx, table):
    """Analyze a single JPEG quantization table.

    Args:
        idx: Table index number.
        table: Quantization table (dict or list).

    Returns:
        Tuple of (average_value, flag_string_or_None).
    """
    table_values = list(table.values()) if isinstance(table, dict) else list(table)
    avg = sum(table_values) / len(table_values)
    print(f"    Table {idx}: avg quantization = {avg:.2f}")
    flag = (
        f"Table {idx}: high avg ({avg:.1f}) -- heavy compression or re-saves"
        if avg > 15
        else None
    )
    return round(avg, 2), flag


def _print_jpeg_flags(flags):
    """Print JPEG compression flags or a normal-status message.

    Args:
        flags: List of flag description strings.
    """
    if flags:
        print("\n  Compression flags:")
        for f in flags:
            print(f"    >> {f}")
    else:
        print("  Compression tables appear normal.")


def _check_jpeg_compression(image_path):
    """Analyze JPEG quantization tables for compression artifacts.

    Args:
        image_path: Path to the image file.

    Returns:
        Report dictionary with table averages and flags.
    """
    _section("9. JPEG COMPRESSION ANALYSIS")
    img = PIL.Image.open(image_path)
    qtables = img.quantization if hasattr(img, "quantization") else None
    if qtables is None:
        print("  Not a JPEG or no quantization tables found.")
        return {"flags": []}
    report = {"num_tables": len(qtables), "flags": []}
    for idx, table in qtables.items():
        avg, flag = _analyze_qtable(idx, table)
        report[f"table_{idx}_avg"] = avg
        if flag:
            report["flags"].append(flag)
    _print_jpeg_flags(report["flags"])
    return report


# ===========================================================================
# Markdown Report Builder: Section helpers (each returns list of strings)
# ===========================================================================


def _md_header(d):
    """Build the markdown report header with file info and date.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    return [
        "# Comprehensive Forensic Analysis Report",
        "",
        f"**File:** `{d['filename']}`  ",
        f"**Dimensions:** {d['img_w']} x {d['img_h']} px  ",
        f"**Format:** {d['img_format']} ({d['img_mode']})  ",
        f"**Date of Analysis:** {d['timestamp']}  ",
        "",
        "---",
        "",
    ]


def _md_verdict_high(d):
    """Build verdict blockquote for highly suspicious images.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    return [
        "> Combined, these indicators strongly suggest the image was **fabricated,",
        "> composited, or heavily manipulated** -- it did not come directly from a phone or camera sensor.",
    ]


def _md_verdict_moderate(d):
    """Build verdict blockquote for suspicious images.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    return [
        "> These indicators suggest the image has been **edited or processed through",
        "> image manipulation software**.",
    ]


def _md_verdict(d):
    """Build the verdict section of the markdown report.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = [f"## Verdict: {d['verdict_label']}", ""]
    lines.append(
        f"> **{len(d['findings'])} forensic finding(s), severity score: {d['total_severity']}.**"
    )
    if d["total_severity"] >= 8:
        lines.extend(_md_verdict_high(d))
    elif d["total_severity"] >= 5:
        lines.extend(_md_verdict_moderate(d))
    lines.extend(["", "---", ""])
    return lines


def _md_exif_found(exif):
    """Build markdown table of found EXIF tags.

    Args:
        exif: Dictionary of EXIF tag names to values.

    Returns:
        List of markdown lines.
    """
    lines = ["### What was found", ""]
    lines.append(
        f"**Total EXIF tags: {len(exif)}** (a real camera photo typically has 30-80+)"
    )
    lines.extend(["", "| Tag | Value |", "|-----|-------|"])
    for k, v in sorted(exif.items()):
        val = str(v)[:100] + "..." if len(str(v)) > 100 else str(v)
        lines.append(f"| {k} | {val} |")
    return lines


def _md_exif_found_or_empty(exif):
    """Build EXIF found table or empty-data notice.

    Args:
        exif: Dictionary of EXIF tag names to values (may be empty).

    Returns:
        List of markdown lines.
    """
    if exif:
        return _md_exif_found(exif)
    return ["> **NO EXIF DATA** -- this image contains zero camera metadata tags."]


def _md_exif_missing(exif):
    """Build markdown table of missing critical EXIF fields.

    Args:
        exif: Dictionary of EXIF tag names to values.

    Returns:
        List of markdown lines.
    """
    missing = {k: v for k, v in ALL_EXPECTED_FIELDS.items() if k not in exif}
    if not missing:
        return []
    lines = [
        "### What is MISSING (critical)",
        "",
        "| Missing Field | Significance |",
        "|---------------|-------------|",
    ]
    for field, meaning in missing.items():
        lines.append(f"| **{field}** | {meaning} |")
    lines.append("")
    if len(missing) >= 10:
        lines.append(
            "> **Every single camera hardware field is absent.** A genuine photo from any phone or camera "
            "always writes Make, Model, ISO, shutter speed, and DateTime. Their complete absence means this "
            "image was **not produced by a camera sensor** -- it was created or exported by software."
        )
        lines.append("")
    return lines


def _md_ps_block_row(block):
    """Build a single markdown table row for a Photoshop resource block.

    Args:
        block: Block dict with 'id', 'size', and 'data' keys.

    Returns:
        Single markdown table row string.
    """
    rid = f"0x{block['id']:04X} ({block['id']})"
    rname = PHOTOSHOP_RESOURCE_NAMES.get(block["id"], "Unknown")
    rsize = f"{block['size']} bytes"
    if block["id"] == 0x0425 and block["size"] == 16:
        return f"| {rid} | {rname} | {rsize} | `{block['data'].hex()}` |"
    if block["id"] == 0x0404:
        contents = (
            "Empty -- IPTC metadata deliberately cleared"
            if block["size"] == 0
            else "IPTC data present"
        )
        return f"| {rid} | {rname} | {rsize} | {contents} |"
    return f"| {rid} | {rname} | {rsize} | |"


def _md_ps_block_table(ps_blocks):
    """Build the Photoshop resource block proof table in markdown.

    Args:
        ps_blocks: List of parsed photoshop block dicts.

    Returns:
        List of markdown lines.
    """
    lines = [
        "### Photoshop Resource Block Detected",
        "",
        "The file headers contain Adobe 8BIM resource blocks. These are Adobe-proprietary binary "
        "markers that **only exist** in files saved through Photoshop or compatible software "
        "(Lightroom, Bridge). A photo taken directly by a phone/camera and never opened in "
        "Photoshop will NEVER contain 8BIM resource blocks.",
        "",
        "#### Raw Binary Proof",
        "",
        "| Resource ID | Name (Adobe Spec) | Size | Contents |",
        "|-------------|-------------------|------|----------|",
    ]
    for block in ps_blocks:
        lines.append(_md_ps_block_row(block))
    lines.append("")
    return lines


def _md_caption_digest(ps_blocks):
    """Build caption digest analysis section if an empty-string MD5 is found.

    Args:
        ps_blocks: List of parsed photoshop block dicts.

    Returns:
        List of markdown lines.
    """
    md5_empty = hashlib.md5(b"").hexdigest()
    for block in ps_blocks:
        if block["id"] == 0x0425 and block["size"] == 16:
            digest_hex = block["data"].hex()
            if digest_hex == md5_empty:
                return [
                    "#### What the Caption Digest reveals",
                    "",
                    f"The 16-byte Caption Digest value is: `{digest_hex}`",
                    "",
                    "This is the **MD5 hash of an empty string** -- a well-known constant. Photoshop computes "
                    "an MD5 digest of the caption/description field. The match means the caption was "
                    "**intentionally blanked out** -- consistent with scrubbing identifying information "
                    "from a manipulated image.",
                    "",
                ]
    return []


def _md_photoshop_section(d):
    """Build the complete Photoshop proof section in markdown.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    if not d["ps_blocks"]:
        return []
    lines = _md_ps_block_table(d["ps_blocks"])
    lines.extend(_md_caption_digest(d["ps_blocks"]))
    lines.append("")
    return lines


def _md_dpi_note(exif):
    """Build the 72 DPI warning note if applicable.

    Args:
        exif: Dictionary of EXIF tag names to values.

    Returns:
        List of markdown lines.
    """
    dpi_val = None
    if "XResolution" in exif:
        xr = exif["XResolution"]
        try:
            dpi_val = float(xr) if not isinstance(xr, tuple) else xr[0] / xr[1]
        except Exception:
            pass
    if not (dpi_val and dpi_val <= 72):
        return []
    return [
        "### 72 DPI Resolution",
        "",
        "The image is set to 72 DPI -- the standard web/screen export resolution. Camera photos "
        "are typically 300 DPI or set to the sensor's native resolution. 72 DPI is what Photoshop "
        "and similar tools default to when creating new documents or exporting for web.",
        "",
    ]


def _md_exif_section(d):
    """Build the complete EXIF metadata analysis markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = ["## 1. EXIF Metadata Analysis", ""]
    lines.extend(_md_exif_found_or_empty(d["exif"]))
    lines.append("")
    lines.extend(_md_exif_missing(d["exif"]))
    lines.extend(_md_photoshop_section(d))
    lines.extend(_md_dpi_note(d["exif"]))
    lines.extend(["---", ""])
    return lines


def _md_ela_grid(d):
    """Build ELA grid statistics markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    return [
        "### Grid Analysis (8x8)",
        "",
        f"- **Overall mean error:** {d['g_mean']:.2f}",
        f"- **Standard deviation:** {d['g_std']:.2f}",
        f"- **Hotspot threshold (mean + 2s):** {d['thresh']:.2f}",
        "",
    ]


def _md_hotspot_row(h):
    """Build a single markdown table row for an ELA hotspot.

    Args:
        h: Hotspot cell data dictionary.

    Returns:
        Single markdown table row string.
    """
    loc = _get_cell_location(h["row"], h["col"], 8)
    gc = f"Row {h['row']}, Col {h['col']}"
    region = f"({h['x1']},{h['y1']})-({h['x2']},{h['y2']})"
    chans = f"R={h['max_per_channel'][0]}, G={h['max_per_channel'][1]}, B={h['max_per_channel'][2]}"
    return f"| **{loc}** | {gc} | {region} | **{h['mean_error']:.2f}** | {chans} |"


def _md_ela_hotspots(d):
    """Build ELA hotspot detection markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    if not d["hotspots"]:
        return ["No hotspot cells detected above threshold.", ""]
    lines = [
        f"### {len(d['hotspots'])} Hotspot(s) Detected",
        "",
        "| Location | Grid Cell | Pixel Region | Mean Error | Max Channel Errors |",
        "|----------|-----------|--------------|------------|-------------------|",
    ]
    for h in d["hotspots"]:
        lines.append(_md_hotspot_row(h))
    lines.extend(
        [
            "",
            "These hotspot regions compress differently from the rest of the image, "
            "which is consistent with content being **pasted, cloned, or digitally altered**.",
            "",
        ]
    )
    return lines


def _md_ela_brightness(d):
    """Build ELA brightness distribution markdown table.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    if "brightness_dist" not in d["ela"]:
        return []
    lines = [
        "### ELA Brightness Distribution",
        "",
        "| Brightness Range | Percentage |",
        "|-----------------|-----------|",
    ]
    for label, pct in d["ela"]["brightness_dist"].items():
        pct_str = f"{pct:.2f}%" if pct >= 0.01 else "<0.01%"
        lines.append(f"| {label} | {pct_str} |")
    lines.append("")
    return lines


def _md_ela_image(d):
    """Build ELA image details markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    return [
        "### ELA Image",
        "",
        f"- **File:** `{d['ela']['ela_image_saved']}`",
        f"- **Mean error (R,G,B):** {d['ela']['mean_error_rgb']}",
        f"- **Std-dev (R,G,B):** {d['ela']['stddev_rgb']}",
        f"- **Max pixel error:** {d['ela']['max_error']}",
        "",
        "---",
        "",
    ]


def _md_ela_section(d):
    """Build the complete ELA markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = [
        "## 2. Error Level Analysis (ELA)",
        "",
        "ELA resaves the image at a known JPEG quality and computes the pixel-by-pixel difference. "
        "In an unedited photo, error levels are uniform. Edited regions -- pasted objects, cloned areas, "
        "AI-generated elements -- compress differently and appear as **bright spots** in the ELA output.",
        "",
    ]
    lines.extend(_md_ela_grid(d))
    lines.extend(_md_ela_hotspots(d))
    lines.extend(_md_ela_brightness(d))
    lines.extend(_md_ela_image(d))
    return lines


def _md_multi_quality(d):
    """Build multi-quality ELA comparison markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = [
        "## 3. Multi-Quality ELA Comparison",
        "",
        "By resaving at multiple JPEG quality levels, we can estimate the quality "
        "the image was originally saved at:",
        "",
        "| Quality | Mean Error (R,G,B) | Max Error | Notes |",
        "|---------|-------------------|-----------|-------|",
    ]
    for r in d["mq_results"]:
        avg = sum(r["mean_rgb"]) / 3
        note = ""
        if r["quality"] >= 85 and avg < 1.0:
            note = "Very low -- may match original quality"
        elif r["quality"] >= 85 and avg < 2.0:
            note = "Low error"
        lines.append(
            f"| {r['quality']} | {r['mean_rgb']} | {r['max_error']} | {note} |"
        )
    lines.extend(
        ["", f"**Estimated original JPEG quality:** ~{d['best_q']['quality']}"]
    )
    if d["best_q"]["quality"] >= 95:
        lines.append(
            "This is consistent with Photoshop 'Maximum' quality export, "
            "not a typical phone camera JPEG (usually 80-92)."
        )
    lines.extend(["", "---", ""])
    return lines


def _md_image_stats(d):
    """Build image statistics markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = ["## 4. Image Statistics", "", "| Metric | Value |", "|--------|-------|"]
    for k, v in d["stats"].items():
        if k != "flags":
            lines.append(f"| {k} | {v} |")
    lines.append("")
    if d["stats"].get("flags"):
        lines.append("**Flags:**")
        for f in d["stats"]["flags"]:
            lines.append(f"- {f}")
        lines.append("")
    lines.extend(["---", ""])
    return lines


def _md_edge_section(d):
    """Build edge and boundary analysis markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = [
        "## 5. Edge & Boundary Analysis",
        "",
        "Edge detection looks for unnatural boundaries that could indicate "
        "composited elements pasted onto the image.",
        "",
        "| Quadrant | Mean Edge Intensity |",
        "|----------|-------------------|",
    ]
    for qname, qval in d["edges"].items():
        lines.append(f"| {qname} | {qval:.2f} |")
    lines.append("")
    vals = list(d["edges"].values())
    if max(vals) > 2 * min(vals) and min(vals) > 1:
        lines.append(
            "> **Edge density imbalance** -- one region has significantly different edge characteristics."
        )
    else:
        lines.append(
            "Edge density is relatively balanced -- no obvious compositing seams detected."
        )
    lines.extend(["", "---", ""])
    return lines


def _md_channel_section(d):
    """Build color channel correlation markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = [
        "## 6. Color Channel Correlation",
        "",
        "Natural photographs have high correlation between R, G, and B channels "
        "because real-world lighting affects all channels similarly.",
        "",
        "| Channel Pair | Pearson Correlation |",
        "|-------------|-------------------|",
        f"| R-G | {d['channels']['rg']:.4f} |",
        f"| R-B | {d['channels']['rb']:.4f} |",
        f"| G-B | {d['channels']['gb']:.4f} |",
        "",
    ]
    min_corr = min(d["channels"].values())
    if min_corr >= 0.75:
        lines.append(
            f"All correlations above {min_corr:.2f} -- falls in the normal range for a natural photograph."
        )
    elif min_corr >= 0.5:
        lines.append(
            f"Moderate correlation (min={min_corr:.2f}) -- possible processing artifacts."
        )
    else:
        lines.append(
            f"Low correlation (min={min_corr:.2f}) -- unusual for natural photographs."
        )
    lines.extend(["", "---", ""])
    return lines


def _md_noise_grid(d):
    """Build noise grid code block for the markdown report.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = ["### Noise Levels by Region (4x4 grid)", "", "```"]
    for row in range(4):
        line = "  "
        for col in range(4):
            line += f"  {d['noise_vals'].get((row, col), 0):5.2f}"
        lines.append(line)
    lines.extend(["```", ""])
    return lines


def _md_noise_stats_table(d):
    """Build noise statistics markdown table with interpretation.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = [
        "| Metric | Value |",
        "|--------|-------|",
        f"| Mean noise level | {d['noise_mean']:.2f} |",
        f"| Noise standard deviation | {d['noise_std']:.2f} |",
        f"| **Coefficient of variation** | **{d['noise_cv']:.3f}** |",
        "",
    ]
    min_noise = min(d["noise_vals"].values())
    max_noise = max(d["noise_vals"].values())
    ratio = max_noise / min_noise if min_noise > 0 else 0
    if d["noise_cv"] > 0.3:
        lines.append(
            f"A CV of **{d['noise_cv']:.2f} is highly inconsistent**. The lowest region ({min_noise:.2f}) "
            f"vs highest ({max_noise:.2f}) is a {ratio:.1f}x difference. In a genuine single-exposure photo, "
            f"noise should be much more uniform. This variation is consistent with **different parts of the "
            f"image originating from different sources** or being processed differently."
        )
    elif d["noise_cv"] > 0.2:
        lines.append(
            f"A CV of **{d['noise_cv']:.2f} is moderately inconsistent**. "
            f"Lowest ({min_noise:.2f}) vs highest ({max_noise:.2f}) = {ratio:.1f}x difference."
        )
    else:
        lines.append(f"Noise is consistent (CV={d['noise_cv']:.2f}).")
    lines.append("")
    return lines


def _md_noise_section(d):
    """Build the complete noise analysis markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = [
        "## 7. Noise Analysis",
        "",
        "Genuine photographs have consistent noise from the camera sensor across the entire image. "
        "When regions are pasted, cloned, or generated separately, they carry **different noise "
        "signatures**, resulting in inconsistent noise distribution.",
        "",
    ]
    lines.extend(_md_noise_grid(d))
    lines.extend(_md_noise_stats_table(d))
    lines.extend(["---", ""])
    return lines


def _md_jpeg_section(d):
    """Build JPEG compression analysis markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = ["## 8. JPEG Compression Analysis", ""]
    if "num_tables" in d["jpeg"]:
        for k, v in d["jpeg"].items():
            if k not in ("flags", "num_tables"):
                lines.append(f"- **{k}:** {v}")
        if d["jpeg"].get("flags"):
            for f in d["jpeg"]["flags"]:
                lines.append(f"- {f}")
        else:
            lines.append("Compression tables appear normal.")
    else:
        lines.append("Not a JPEG or no quantization tables found.")
    lines.extend(["", "---", ""])
    return lines


def _md_advanced_forensics(d):
    """Build advanced forensics markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    adv = d.get("advanced", {})
    if not adv:
        return []
    lines = _md_advanced_header()
    lines.extend(_md_advanced_rows(adv))
    lines.extend(["", "---", ""])
    return lines


def _md_advanced_header():
    """Build the heading/table header for advanced markdown section.

    Returns:
        List of markdown lines.
    """
    return [
        "## 11. Advanced Forensics",
        "",
        "| Check | Metric | Value |",
        "|------|--------|-------|",
    ]


def _md_advanced_rows(adv):
    """Build metric rows for advanced markdown section.

    Args:
        adv: Advanced forensics dictionary.

    Returns:
        List of markdown table rows.
    """
    hist = adv.get("histogram", {})
    grad = adv.get("gradient", {})
    copy_move = adv.get("copy_move", {})
    ghost = adv.get("jpeg_ghost", {})
    return [
        f"| Histogram | Empty-bin ratio | {hist.get('empty_ratio', 0):.4f} |",
        f"| Histogram | Comb score | {hist.get('score', 0):.4f} |",
        f"| Gradient | Consistency CV | {grad.get('gradient_cv', 0):.4f} |",
        f"| Copy-Move | Duplicate ratio | {copy_move.get('duplicate_ratio', 0):.4f} |",
        f"| JPEG Ghost | Instability score | {ghost.get('score', 0):.4f} |",
    ]


def _md_auth_header():
    """Build markdown header for authenticity fusion section.

    Returns:
        List of markdown header lines.
    """
    return [
        "## 12. Authenticity Fusion",
        "",
        "| Metric | Value |",
        "|--------|-------|",
    ]


def _md_auth_rows(assessment):
    """Build markdown rows for authenticity fusion metrics.

    Args:
        assessment: Authenticity assessment dictionary.

    Returns:
        List of markdown rows.
    """
    probability = 100.0 * assessment.get("tamper_probability", 0.0)
    return [
        f"| Tamper probability | **{probability:.2f}%** |",
        f"| Confidence | **{assessment.get('confidence', 'LOW')}** |",
        f"| Verdict | **{assessment.get('verdict', 'INCONCLUSIVE')}** |",
        f"| Consensus | {assessment.get('consensus', 0.0):.4f} |",
    ]


def _md_authenticity_section(d):
    """Build complete markdown section for authenticity fusion output.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    assessment = d.get("assessment", {})
    if not assessment:
        return []
    lines = _md_auth_header()
    lines.extend(_md_auth_rows(assessment))
    lines.extend(["", "---", ""])
    return lines


def _md_stego_chi_header():
    """Return chi-square table markdown header lines.

    Returns:
        List of header markdown lines.
    """
    return [
        "### Chi-Square LSB Analysis",
        "",
        "| Channel | Chi-Sq | DoF | p-value | Verdict |",
        "|---------|--------|-----|---------|---------|",
    ]


def _md_stego_chi_row(ch, r):
    """Format a single chi-square result as a markdown table row.

    Args:
        ch: Channel name (R, G, or B).
        r: Channel result dictionary.

    Returns:
        Formatted markdown table row string.
    """
    return (
        f"| {ch} | {r['chi_square']:.2f} | {r['dof']} "
        f"| {r['p_value']:.4f} | **{r['verdict']}** |"
    )


def _md_stego_chi_table(stego):
    """Build chi-square steganalysis markdown table.

    Args:
        stego: Steganography scan results dictionary.

    Returns:
        List of markdown lines.
    """
    chi = stego["chi"]
    lines = _md_stego_chi_header()
    for ch in "RGB":
        lines.append(_md_stego_chi_row(ch, chi[ch]))
    lines.extend(["", f"**Overall:** {chi['overall']}", ""])
    return lines


def _md_stego_spa_header():
    """Return SPA table markdown header lines.

    Returns:
        List of header markdown lines.
    """
    return [
        "### Sample Pairs Analysis (SPA)",
        "",
        "| Channel | Est. Rate |",
        "|---------|-----------|",
    ]


def _md_stego_spa_table(stego):
    """Build SPA embedding rate markdown table.

    Args:
        stego: Steganography scan results dictionary.

    Returns:
        List of markdown lines.
    """
    spa = stego["spa"]
    lines = _md_stego_spa_header()
    for ch in "RGB":
        lines.append(f"| {ch} | {spa[ch]:.4f} |")
    lines.extend(
        ["", f"**Overall estimated embedding rate:** {spa['overall']:.4f}", ""]
    )
    return lines


def _md_stego_rs_header():
    """Return RS table markdown header lines.

    Returns:
        List of header markdown lines.
    """
    return [
        "### RS (Regular-Singular) Analysis",
        "",
        "| Channel | Rm | Sm | R-m | S-m | Rate |",
        "|---------|----|----|-----|-----|------|",
    ]


def _md_stego_rs_row(ch, r):
    """Format a single RS result as a markdown table row.

    Args:
        ch: Channel name (R, G, or B).
        r: Channel result dictionary.

    Returns:
        Formatted markdown table row string.
    """
    return (
        f"| {ch} | {r['rm']} | {r['sm']} "
        f"| {r['r_m']} | {r['s_m']} | {r['rate']:.4f} |"
    )


def _md_stego_rs_table(stego):
    """Build RS steganalysis markdown table.

    Args:
        stego: Steganography scan results dictionary.

    Returns:
        List of markdown lines.
    """
    rs = stego["rs"]
    lines = _md_stego_rs_header()
    for ch in "RGB":
        lines.append(_md_stego_rs_row(ch, rs[ch]))
    lines.extend(["", f"**Overall RS embedding estimate:** {rs['overall']:.4f}", ""])
    return lines


def _md_stego_bitplane_header():
    """Return bit-plane entropy table markdown header lines.

    Returns:
        List of header markdown lines.
    """
    return [
        "### Bit-Plane Entropy",
        "",
        "| Channel | Bit 0 (LSB) | Bit 1 | Bit 2 | Bit 7 (MSB) |",
        "|---------|-------------|-------|-------|-------------|",
    ]


def _md_stego_bitplane_row(ch, e):
    """Format a single bit-plane entropy row as markdown.

    Args:
        ch: Channel name (R, G, or B).
        e: List of entropy values for each bit plane.

    Returns:
        Formatted markdown table row string.
    """
    return f"| {ch} | {e[0]:.4f} | {e[1]:.4f} | {e[2]:.4f} | {e[7]:.4f} |"


def _md_stego_bitplane_flags(flags):
    """Build markdown lines for bit-plane anomaly flags.

    Args:
        flags: List of flag description strings.

    Returns:
        List of markdown lines (empty list if no flags).
    """
    lines = []
    for f in flags:
        lines.append(f"- {f}")
    if lines:
        lines.append("")
    return lines


def _md_stego_bitplane(stego):
    """Build bit-plane entropy markdown table.

    Args:
        stego: Steganography scan results dictionary.

    Returns:
        List of markdown lines.
    """
    bp = stego["bitplane"]
    lines = _md_stego_bitplane_header()
    for ch in "RGB":
        lines.append(_md_stego_bitplane_row(ch, bp[ch]))
    lines.append("")
    lines.extend(_md_stego_bitplane_flags(bp["flags"]))
    return lines


def _md_stego_extracted_hit(hit):
    """Format a single extracted hidden message for markdown.

    Args:
        hit: Extraction result dict with 'text' and 'bits' keys.

    Returns:
        List of markdown lines for this hit.
    """
    preview = hit["text"][:300] + "..." if len(hit["text"]) > 300 else hit["text"]
    return [f"**Found at {hit['bits']} bit(s)/channel:**", f"> {preview}", ""]


def _md_stego_extracted(stego):
    """Build extracted hidden message markdown section.

    Args:
        stego: Steganography scan results dictionary.

    Returns:
        List of markdown lines.
    """
    found = stego.get("extracted", [])
    if not found:
        return ["No readable hidden messages found (without password).", ""]
    lines = ["### Extracted Hidden Messages", ""]
    for hit in found:
        lines.extend(_md_stego_extracted_hit(hit))
    return lines


def _md_stego_section_intro():
    """Return the steganography section introduction markdown.

    Returns:
        List of introductory markdown lines.
    """
    return [
        "## 10. Steganography Detection",
        "",
        "Steganography hides secret messages inside image pixels by modifying "
        "the least significant bits (LSBs). Multiple statistical tests detect "
        "whether pixel values show the telltale patterns of LSB embedding.",
        "",
    ]


def _md_stego_section_tables(stego):
    """Build all steganography sub-analysis markdown tables.

    Args:
        stego: Steganography scan results dictionary.

    Returns:
        List of markdown lines for all sub-tables.
    """
    lines = _md_stego_chi_table(stego)
    lines.extend(_md_stego_spa_table(stego))
    lines.extend(_md_stego_rs_table(stego))
    lines.extend(_md_stego_bitplane(stego))
    lines.extend(_md_stego_extracted(stego))
    if "dct" in stego:
        lines.extend(_md_stego_dct_section(stego))
    return lines


def _md_stego_section(d):
    """Build the complete steganography analysis markdown section.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    stego = d.get("stego")
    if not stego:
        return []
    lines = _md_stego_section_intro()
    lines.extend(_md_stego_section_tables(stego))
    lines.extend([f"**Verdict:** {stego['verdict']}", "", "---", ""])
    return lines


def _md_stego_dct_header():
    """Return DCT section markdown header with JPEG note.

    Returns:
        List of markdown header lines.
    """
    return [
        "### DCT Coefficient Analysis (JPEG)",
        "",
        "> **Note:** Pixel-level LSB tests above may show false positives "
        "for JPEG images. JPEG lossy compression creates inherently random "
        "LSBs. The verdict below uses DCT-level analysis instead.",
        "",
    ]


def _md_stego_dct_section(stego):
    """Build the DCT analysis markdown subsection for JPEG images.

    Args:
        stego: Steganography results dictionary containing 'dct' key.

    Returns:
        List of markdown lines.
    """
    dct = stego["dct"]
    if dct is None:
        return ["### DCT Analysis", "", "*OpenCV unavailable.*", ""]
    lines = _md_stego_dct_header()
    lines.extend(_md_stego_dct_jsteg(dct))
    lines.extend(_md_stego_dct_f5(dct))
    return lines


def _md_stego_dct_jsteg(dct):
    """Build JSteg detection markdown table.

    Args:
        dct: DCT analysis results dictionary.

    Returns:
        List of markdown lines.
    """
    return [
        "**JSteg Detection:**",
        "",
        f"- Pair mean ratio: {dct['pair_mean']:.4f} (std: {dct['pair_std']:.4f})",
        f"- Verdict: **{dct['jsteg']}**",
        "",
    ]


def _md_stego_dct_f5(dct):
    """Build F5 detection markdown table.

    Args:
        dct: DCT analysis results dictionary.

    Returns:
        List of markdown lines.
    """
    return [
        "**F5 Detection:**",
        "",
        f"- Zero coefficients: {dct['zero_count']} ({dct['zero_pct']:.1f}%)",
        f"- Verdict: **{dct['f5']}**",
        "",
    ]


def _md_findings_table(d):
    """Build forensic findings summary table in markdown.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    sev_labels = {1: "LOW", 2: "MODERATE", 3: "HIGH"}
    lines = [
        "## Summary of Forensic Findings",
        "",
        "| # | Finding | Severity | Score |",
        "|---|---------|----------|-------|",
    ]
    for i, (desc, sev) in enumerate(d["findings"], 1):
        lines.append(f"| {i} | **{desc}** | {sev_labels.get(sev, '?')} | {sev}/3 |")
    lines.append("")
    return lines


def _md_conclusion(d):
    """Build the conclusion section of the markdown report.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = ["## Conclusion", ""]
    if d["total_severity"] >= 8:
        lines.append(
            "This image is **highly suspicious** and almost certainly not a genuine, unaltered "
            "photograph. The forensic evidence indicates it was either fabricated, composited, or "
            "heavily manipulated. It should not be trusted as an authentic photograph."
        )
    elif d["total_severity"] >= 5:
        lines.append(
            "This image shows **significant signs of manipulation**. It has likely been processed "
            "through image editing software. The combination of findings suggests it should not be "
            "fully trusted as an authentic, unaltered photograph."
        )
    elif d["total_severity"] >= 2:
        lines.append(
            "This image shows **minor concerns** but no overwhelming evidence of manipulation. "
            "Some metadata inconsistencies were found, but they could have benign explanations."
        )
    else:
        lines.append(
            "No significant forensic red flags were detected. The image appears authentic."
        )
    lines.append("")
    return lines


def _md_footer(d):
    """Build the footer line of the markdown report.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    return [
        "---",
        "",
        f"*Generated by [PixelProof](https://github.com/mytechnotalent/pixelproof) on {d['timestamp']}*",
    ]


def _md_early_analysis(d):
    """Build ELA, multi-quality, image stats, and edge markdown sections.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = _md_ela_section(d)
    lines.extend(_md_multi_quality(d))
    lines.extend(_md_image_stats(d))
    lines.extend(_md_edge_section(d))
    return lines


def _md_late_analysis(d):
    """Build channel correlation, noise, JPEG, and stego markdown sections.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = _md_channel_section(d)
    lines.extend(_md_noise_section(d))
    lines.extend(_md_jpeg_section(d))
    lines.extend(_md_stego_section(d))
    lines.extend(_md_advanced_forensics(d))
    lines.extend(_md_authenticity_section(d))
    return lines


def _md_all_analysis(d):
    """Build all forensic analysis markdown sections.

    Args:
        d: Report data dictionary.

    Returns:
        List of markdown lines.
    """
    lines = _md_exif_section(d)
    lines.extend(_md_early_analysis(d))
    lines.extend(_md_late_analysis(d))
    return lines


def _build_markdown_report(data):
    """Build a comprehensive Markdown forensic report from analysis data.

    Args:
        data: Complete report data dictionary with all analysis results.

    Returns:
        The full markdown report as a single string.
    """
    lines = _md_header(data)
    lines.extend(_md_verdict(data))
    lines.extend(_md_all_analysis(data))
    lines.extend(_md_findings_table(data))
    lines.extend(_md_conclusion(data))
    lines.extend(_md_footer(data))
    return "\n".join(lines)


# ===========================================================================
# Forensic findings and verdict helpers
# ===========================================================================


def _check_metadata_findings(exif):
    """Evaluate EXIF metadata for forensic findings with severity scores.

    Args:
        exif: Dictionary of EXIF tag names to values.

    Returns:
        List of (description, severity) tuples.
    """
    present = [f for f in CAMERA_FIELDS if f in exif]
    meta_score, meta_details = 0, []
    if not present:
        meta_details.append("no camera hardware fields")
        meta_score += 1
    if "DateTime" not in exif and "DateTimeOriginal" not in exif:
        meta_details.append("no timestamp")
        meta_score += 1
    if "GPSInfo" not in exif:
        meta_details.append("no GPS")
        meta_score += 1
    if meta_score:
        return [(f"Missing metadata ({', '.join(meta_details)})", meta_score)]
    return []


def _check_ela_findings(hotspots, ela):
    """Evaluate ELA results for forensic findings with severity scores.

    Args:
        hotspots: List of hotspot cell data dicts.
        ela: ELA result dictionary.

    Returns:
        List of (description, severity) tuples.
    """
    findings = []
    if hotspots:
        sev = 1 if len(hotspots) <= 1 else (2 if len(hotspots) <= 3 else 3)
        findings.append((f"ELA detected {len(hotspots)} hotspot(s)", sev))
    if ela["max_error"] > 25:
        findings.append(("ELA shows inconsistent error levels", 2))
    return findings


def _check_noise_findings(noise_cv):
    """Evaluate noise analysis for forensic findings with severity scores.

    Args:
        noise_cv: Coefficient of variation for noise levels.

    Returns:
        List of (description, severity) tuples.
    """
    if noise_cv > 0.5:
        return [(f"Highly inconsistent noise (CV={noise_cv:.2f})", 3)]
    if noise_cv > 0.3:
        return [(f"Inconsistent noise (CV={noise_cv:.2f})", 2)]
    if noise_cv > 0.2:
        return [(f"Moderately inconsistent noise (CV={noise_cv:.2f})", 1)]
    return []


def _check_edge_findings(edges):
    """Evaluate edge analysis for forensic findings with severity scores.

    Args:
        edges: Dictionary of {quadrant_name: mean_edge_intensity}.

    Returns:
        List of (description, severity) tuples.
    """
    edge_vals = list(edges.values())
    if max(edge_vals) > 2 * min(edge_vals) and min(edge_vals) > 1:
        return [("Edge density imbalance", 2)]
    return []


def _check_channel_findings(channels):
    """Evaluate channel correlation for forensic findings with severity.

    Args:
        channels: Dictionary with 'rg', 'rb', 'gb' correlation values.

    Returns:
        List of (description, severity) tuples.
    """
    min_corr = min(channels.values())
    if min_corr < 0.5:
        return [(f"Low channel correlation (min={min_corr:.2f})", 3)]
    if min_corr < 0.75:
        return [(f"Moderate channel correlation (min={min_corr:.2f})", 1)]
    return []


def _check_ancillary_findings(stats, jpeg, ps_blocks):
    """Evaluate stats, JPEG, and Photoshop data for forensic findings.

    Args:
        stats: Image statistics report dictionary.
        jpeg: JPEG compression report dictionary.
        ps_blocks: List of Photoshop block dicts.

    Returns:
        List of (description, severity) tuples.
    """
    findings = [(sf, 2) for sf in stats.get("flags", [])]
    findings.extend((jf, 2) for jf in jpeg.get("flags", []))
    if ps_blocks:
        findings.append(("Adobe Photoshop resource block present (8BIM signature)", 2))
    return findings


def _check_stego_findings(stego):
    """Evaluate steganography scan results for forensic findings.

    Args:
        stego: Steganography scan results dictionary, or None.

    Returns:
        List of (description, severity) tuples.
    """
    if not stego:
        return []
    return list(stego.get("findings", []))


def _check_advanced_findings(advanced):
    """Evaluate advanced forensics findings for verdict fusion.

    Args:
        advanced: Advanced forensic results dictionary, or None.

    Returns:
        List of (description, severity) tuples.
    """
    if not advanced:
        return []
    return list(advanced.get("findings", []))


def _compute_all_findings(results):
    """Compute all forensic findings and total severity score.

    Args:
        results: Dictionary of all analysis results.

    Returns:
        Tuple of (findings_list, total_severity_score).
    """
    findings = _check_metadata_findings(results["exif"])
    findings.extend(_check_ela_findings(results["hotspots"], results["ela"]))
    findings.extend(_check_noise_findings(results["noise_cv"]))
    findings.extend(_check_edge_findings(results["edges"]))
    findings.extend(_check_channel_findings(results["channels"]))
    findings.extend(
        _check_ancillary_findings(
            results["stats"], results["jpeg"], results["ps_blocks"]
        )
    )
    findings.extend(_check_stego_findings(results.get("stego")))
    findings.extend(_check_advanced_findings(results.get("advanced")))
    return findings, sum(s for _, s in findings)


# ===========================================================================
# Full forensic analysis orchestrator helpers
# ===========================================================================


def _print_banner(image_path):
    """Print the PixelProof forensic analysis banner.

    Args:
        image_path: Path to the image being analyzed.
    """
    print("\u2554" + "\u2550" * 70 + "\u2557")
    print(
        "\u2551   PIXELPROOF -- COMPREHENSIVE FORENSIC ANALYSIS" + " " * 22 + "\u2551"
    )
    print("\u2551   " + os.path.basename(image_path).ljust(66) + " \u2551")
    print("\u255a" + "\u2550" * 70 + "\u255d")


def _get_image_basics(image_path):
    """Open image briefly to extract basic format information.

    Args:
        image_path: Path to the image file.

    Returns:
        Tuple of (width, height, format_string, mode_string).
    """
    img = PIL.Image.open(image_path)
    w, h = img.size
    fmt = img.format or "Unknown"
    mode = img.mode
    img.close()
    return w, h, fmt, mode


def _print_stego_banner():
    """Print the steganography detection section header and description."""
    _section("10. STEGANOGRAPHY DETECTION")
    print(
        "\n  Steganography hides secret messages inside image pixels by"
        "\n  modifying the least significant bits (LSBs). Multiple"
        "\n  statistical tests detect whether pixel values show the"
        "\n  telltale patterns of LSB embedding."
    )


def _run_stego_detection(image_path):
    """Run steganography detection as analysis pass 10.

    For JPEG images, adds DCT-level analysis and uses only DCT results
    for the verdict, since pixel-level LSB tests produce false positives
    on lossy-compressed images.

    Args:
        image_path: Path to the image file.

    Returns:
        Steganography scan results dictionary.
    """
    _print_stego_banner()
    return _run_stego_sub_analyses(image_path)


def _print_stego_chi_header():
    """Print chi-square analysis table header to the terminal."""
    print(f"\n  --- Chi-Square LSB Analysis ---\n")
    print(
        f"    {'Channel':10s} {'Chi-Sq':12s} {'DoF':6s} {'p-value':10s} {'Verdict':10s}"
    )
    print(f"    {'-' * 10} {'-' * 12} {'-' * 6} {'-' * 10} {'-' * 10}")


def _print_stego_chi_row(ch, r):
    """Print one chi-square result row to the terminal.

    Args:
        ch: Channel name (R, G, or B).
        r: Channel result dictionary.
    """
    print(
        f"    {ch:10s} {r['chi_square']:12.2f} {r['dof']:6d} {r['p_value']:10.4f} {r['verdict']:10s}"
    )


def _print_stego_chi(chi):
    """Print chi-square steganalysis results for the terminal.

    Args:
        chi: Chi-square analysis results dictionary.
    """
    _print_stego_chi_header()
    for ch in "RGB":
        _print_stego_chi_row(ch, chi[ch])
    print(f"\n    Overall: {chi['overall']}")


def _print_stego_spa(spa):
    """Print SPA results for the terminal.

    Args:
        spa: SPA results dictionary.
    """
    print(f"\n  --- Sample Pairs Analysis (SPA) ---\n")
    print(f"    {'Channel':10s} {'Est. Rate':12s}")
    print(f"    {'-' * 10} {'-' * 12}")
    for ch in "RGB":
        print(f"    {ch:10s} {spa[ch]:12.4f}")
    print(f"\n    Overall estimated embedding rate: {spa['overall']:.4f}")


def _print_stego_rs_row(ch, r):
    """Print one RS analysis result row to the terminal.

    Args:
        ch: Channel name (R, G, or B).
        r: Channel result dictionary.
    """
    print(
        f"    {ch:10s} {r['rm']:8d} {r['sm']:8d} {r['r_m']:8d} {r['s_m']:8d} {r['rate']:8.4f}"
    )


def _print_stego_rs(rs):
    """Print RS steganalysis results for the terminal.

    Args:
        rs: RS analysis results dictionary.
    """
    print(f"\n  --- RS (Regular-Singular) Analysis ---\n")
    print(f"    {'Channel':10s} {'Rm':8s} {'Sm':8s} {'R-m':8s} {'S-m':8s} {'Rate':8s}")
    print(f"    {'-' * 10} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8}")
    for ch in "RGB":
        _print_stego_rs_row(ch, rs[ch])
    print(f"\n    Overall RS embedding estimate: {rs['overall']:.4f}")


def _print_stego_bitplane_header():
    """Print bit-plane entropy table header to the terminal."""
    print(f"\n  --- Bit-Plane Entropy Analysis ---\n")
    print(
        f"    {'Channel':10s} {'Bit 0 (LSB)':12s} {'Bit 1':12s} {'Bit 2':12s} {'Bit 7 (MSB)':12s}"
    )
    print(f"    {'-' * 10} {'-' * 12} {'-' * 12} {'-' * 12} {'-' * 12}")


def _print_stego_bitplane_flags(flags):
    """Print bit-plane anomaly flags to the terminal.

    Args:
        flags: List of flag description strings.
    """
    if not flags:
        return
    print("\n    Flags:")
    for f in flags:
        print(f"      >> {f}")


def _print_stego_bitplane(bp):
    """Print bit-plane entropy analysis for the terminal.

    Args:
        bp: Bit-plane analysis results dictionary.
    """
    _print_stego_bitplane_header()
    for ch in "RGB":
        e = bp[ch]
        print(f"    {ch:10s} {e[0]:12.4f} {e[1]:12.4f} {e[2]:12.4f} {e[7]:12.4f}")
    _print_stego_bitplane_flags(bp["flags"])


def _print_stego_extracted(found):
    """Print brute-force LSB extraction results for the terminal.

    Args:
        found: List of successful extraction dicts.
    """
    print(f"\n  --- Brute-Force LSB Extraction ---\n")
    if not found:
        print("    No readable hidden messages found (without password).")
        return
    for hit in found:
        preview = hit["text"][:200] + "..." if len(hit["text"]) > 200 else hit["text"]
        print(f"    FOUND at {hit['bits']} bit(s)/channel:")
        print(f'    >> "{preview}"')


def _print_stego_verdict(verdict, findings):
    """Print steganography verdict to the terminal.

    Args:
        verdict: Verdict string.
        findings: List of (description, severity) tuples.
    """
    print(f"\n    Stego verdict: {verdict}")
    if findings:
        for i, (desc, sev) in enumerate(findings, 1):
            print(f"      {i}. {desc} (severity {sev})")


def _run_stego_chi_spa(image_path):
    """Run chi-square and SPA analyses and print their results.

    Args:
        image_path: Path to the image file.

    Returns:
        Tuple of (chi, spa) results.
    """
    from stego import _chi_square_analysis, _spa_analysis

    chi = _chi_square_analysis(image_path)
    _print_stego_chi(chi)
    spa = _spa_analysis(image_path)
    _print_stego_spa(spa)
    return chi, spa


def _run_stego_rs_bp_extract(image_path):
    """Run RS, bit-plane, and brute-force analyses and print results.

    Args:
        image_path: Path to the image file.

    Returns:
        Tuple of (rs, bp, found) results.
    """
    from stego import _rs_analysis, _analyze_bit_planes, _brute_force_decode

    rs = _rs_analysis(image_path)
    _print_stego_rs(rs)
    bp = _analyze_bit_planes(image_path)
    _print_stego_bitplane(bp)
    found = _brute_force_decode(image_path)
    _print_stego_extracted(found)
    return rs, bp, found


def _run_stego_lossless_branch(chi, spa, rs, bp, found):
    """Handle steganography verdict for lossless images.

    Args:
        chi: Chi-square results.
        spa: SPA results.
        rs: RS results.
        bp: Bit-plane results.
        found: Brute-force extraction hits.

    Returns:
        Steganography scan results dictionary.
    """
    from stego import _compute_scan_verdict

    verdict, findings = _compute_scan_verdict(chi, spa, rs, bp, found)
    _print_stego_verdict(verdict, findings)
    return _build_stego_result(chi, spa, rs, bp, found, verdict, findings, None)


def _run_stego_sub_analyses(image_path):
    """Execute all steganography sub-analyses and print results.

    For JPEG images, additionally runs DCT-level analysis and computes
    the verdict using only DCT results (pixel-level tests are unreliable
    for JPEG). For lossless formats, uses pixel-level tests as before.

    Args:
        image_path: Path to the image file.

    Returns:
        Steganography scan results dictionary.
    """
    from stego import _is_jpeg_file

    chi, spa = _run_stego_chi_spa(image_path)
    rs, bp, found = _run_stego_rs_bp_extract(image_path)
    if _is_jpeg_file(image_path):
        return _run_stego_jpeg_branch(image_path, chi, spa, rs, bp, found)
    return _run_stego_lossless_branch(chi, spa, rs, bp, found)


def _run_stego_jpeg_branch(image_path, chi, spa, rs, bp, found):
    """Handle steganography results for JPEG images in deep analysis.

    Prints a JPEG warning, runs DCT analysis, and computes the verdict
    using only DCT-level results.

    Args:
        image_path: Path to the JPEG image.
        chi: Chi-square results (informational only).
        spa: SPA results (informational only).
        rs: RS results (informational only).
        bp: Bit-plane results (informational only).
        found: Brute-force extraction hits.

    Returns:
        Steganography scan results dictionary with DCT data.
    """
    from stego import _jpeg_dct_analysis, _compute_jpeg_verdict

    _print_stego_jpeg_warning()
    dct = _jpeg_dct_analysis(image_path)
    _print_stego_dct(dct)
    verdict, findings = _compute_jpeg_verdict(dct, found)
    _print_stego_verdict(verdict, findings)
    return _build_stego_result(chi, spa, rs, bp, found, verdict, findings, dct)


def _print_stego_jpeg_warning():
    """Print JPEG false-positive warning in deep analysis output."""
    print(f"\n  {'*' * 60}")
    print(f"  * JPEG FORMAT: pixel-level LSB tests above may show")
    print(f"  * false positives. JPEG lossy compression creates random")
    print(f"  * LSBs. Verdict uses DCT-level analysis instead.")
    print(f"  {'*' * 60}")


def _print_stego_dct(dct):
    """Print DCT analysis results for the terminal.

    Args:
        dct: DCT analysis results dictionary, or None.
    """
    if dct is None:
        print("\n  --- DCT Analysis ---")
        print("    OpenCV unavailable; DCT analysis skipped.")
        return
    _print_stego_dct_jsteg(dct)
    _print_stego_dct_f5(dct)


def _print_stego_dct_jsteg(dct):
    """Print JSteg detection results for the terminal.

    Args:
        dct: DCT analysis results dictionary.
    """
    print(f"\n  --- DCT JSteg Detection ---")
    print(f"    Pair mean ratio: {dct['pair_mean']:.4f} (std: {dct['pair_std']:.4f})")
    print(f"    JSteg verdict: {dct['jsteg']}")


def _print_stego_dct_f5(dct):
    """Print F5 detection results for the terminal.

    Args:
        dct: DCT analysis results dictionary.
    """
    print(f"\n  --- DCT F5 Detection ---")
    print(f"    Zero coefficients: {dct['zero_count']} ({dct['zero_pct']:.1f}%)")
    print(f"    F5 verdict: {dct['f5']}")


def _build_stego_pixel_dict(chi, spa, rs, bp):
    """Build the pixel-level analysis portion of stego results.

    Args:
        chi: Chi-square results.
        spa: SPA results.
        rs: RS results.
        bp: Bit-plane results.

    Returns:
        Dictionary with pixel-level stego analysis data.
    """
    return {"chi": chi, "spa": spa, "rs": rs, "bitplane": bp}


def _build_stego_base_dict(chi, spa, rs, bp, found, verdict, findings):
    """Build the base stego results dictionary without DCT data.

    Args:
        chi: Chi-square results.
        spa: SPA results.
        rs: RS results.
        bp: Bit-plane results.
        found: Brute-force extraction hits.
        verdict: Final verdict string.
        findings: List of (description, severity) tuples.

    Returns:
        Dictionary with pixel-level stego results and verdict.
    """
    results = _build_stego_pixel_dict(chi, spa, rs, bp)
    results["extracted"] = found
    results["verdict"] = verdict
    results["findings"] = findings
    return results


def _build_stego_result(chi, spa, rs, bp, found, verdict, findings, dct):
    """Assemble steganography scan results into a dictionary.

    Args:
        chi: Chi-square results.
        spa: SPA results.
        rs: RS results.
        bp: Bit-plane results.
        found: Brute-force extraction hits.
        verdict: Final verdict string.
        findings: List of (description, severity) tuples.
        dct: DCT analysis results (None for lossless images).

    Returns:
        Comprehensive results dictionary.
    """
    results = _build_stego_base_dict(chi, spa, rs, bp, found, verdict, findings)
    if dct is not None:
        results["dct"] = dct
    return results


def _print_advanced_forensics_header():
    """Print the advanced forensics section header.

    Returns:
        None.
    """
    _section("11. ADVANCED FORENSICS")


def _print_advanced_forensics_summary(advanced):
    """Print key metrics from advanced forensic analysis.

    Args:
        advanced: Advanced forensics result dictionary.
    """
    print(f"\n  Histogram score:  {advanced['histogram']['score']:.4f}")
    print(f"  Gradient CV:      {advanced['gradient']['gradient_cv']:.4f}")
    print(f"  Copy-move ratio:  {advanced['copy_move']['duplicate_ratio']:.4f}")
    print(f"  JPEG ghost score: {advanced['jpeg_ghost']['score']:.4f}")


def _run_advanced_forensics(image_path):
    """Run advanced forensics and print section output.

    Args:
        image_path: Path to the image file.

    Returns:
        Advanced forensics result dictionary.
    """
    _print_advanced_forensics_header()
    advanced = analyze_advanced_forensics(image_path)
    _print_advanced_forensics_summary(advanced)
    return advanced


def _run_all_analyses(image_path):
    """Execute all 10 forensic analysis passes on an image.

    Args:
        image_path: Path to the image file.

    Returns:
        Dictionary with all analysis results keyed by pass name.
    """
    exif, info_keys, ps_blocks = _full_exif_dump(image_path)
    grid_data, hotspots, g_mean, g_std, thresh = _grid_ela_analysis(image_path)
    ela = _perform_ela(image_path)
    mq_results, best_q = _multi_quality_ela(image_path)
    stats = _analyze_image_stats(image_path)
    edges, edge_mean, edge_std = _edge_analysis(image_path)
    channels = _channel_correlation(image_path)
    noise_vals, noise_mean, noise_std, noise_cv = _noise_analysis(image_path)
    jpeg = _check_jpeg_compression(image_path)
    stego = _run_stego_detection(image_path)
    advanced = _run_advanced_forensics(image_path)
    return {
        "exif": exif,
        "info_keys": info_keys,
        "ps_blocks": ps_blocks,
        "grid_data": grid_data,
        "hotspots": hotspots,
        "g_mean": g_mean,
        "g_std": g_std,
        "thresh": thresh,
        "ela": ela,
        "mq_results": mq_results,
        "best_q": best_q,
        "stats": stats,
        "edges": edges,
        "edge_mean": edge_mean,
        "edge_std": edge_std,
        "channels": channels,
        "noise_vals": noise_vals,
        "noise_mean": noise_mean,
        "noise_std": noise_std,
        "noise_cv": noise_cv,
        "jpeg": jpeg,
        "stego": stego,
        "advanced": advanced,
    }


def _print_finding_row(i, desc, sev):
    """Print a single finding row in the terminal verdict.

    Args:
        i: Finding number (1-based).
        desc: Description of the finding.
        sev: Severity score (1-3).
    """
    sev_labels = {1: "LOW", 2: "MOD", 3: "HIGH"}
    bar = "\u25aa" * sev
    print(f"    {i}. [{bar:<3s}] [{sev_labels.get(sev, '?'):4s}] {desc}")


def _determine_verdict_label(total_severity):
    """Determine the verdict label and print the verdict to terminal.

    Args:
        total_severity: Total severity score across all findings.

    Returns:
        Verdict label string.
    """
    if total_severity >= 8:
        print("\n  \U0001f534 HIGHLY SUSPICIOUS")
        print(
            "\n  This image is almost certainly not a genuine, unaltered"
            "\n  photograph. The forensic evidence indicates fabrication,"
            "\n  compositing, or heavy manipulation."
        )
        return "HIGHLY SUSPICIOUS"
    if total_severity >= 5:
        print("\n  \U0001f7e1 SUSPICIOUS")
        print(
            "\n  This image shows significant signs of manipulation."
            "\n  It has likely been processed through image editing software."
        )
        return "SUSPICIOUS"
    if total_severity >= 2:
        print("\n  \U0001f7e1 MINOR CONCERN")
        return "MINOR CONCERN"
    print("\n  \U0001f7e2 NO RED FLAGS")
    return "NO RED FLAGS"


def _print_auth_summary(assessment):
    """Print authenticity fusion summary to terminal.

    Args:
        assessment: Authenticity assessment dictionary.
    """
    probability = 100.0 * assessment.get("tamper_probability", 0.0)
    print(f"\n  Tamper probability: {probability:.2f}%")
    print(f"  Confidence: {assessment.get('confidence', 'LOW')}")
    print(f"  Fusion verdict: {assessment.get('verdict', 'INCONCLUSIVE')}")


def _print_terminal_verdict(findings, total_severity, ela, assessment):
    """Print the complete terminal verdict section.

    Args:
        findings: List of (description, severity) tuples.
        total_severity: Total severity score.
        ela: ELA result dictionary.

    Returns:
        Verdict label string.
    """
    _section("FINAL VERDICT")
    print(f"\n  Findings: {len(findings)}  |  Severity score: {total_severity}")
    for i, (desc, sev) in enumerate(findings, 1):
        _print_finding_row(i, desc, sev)
    _print_auth_summary(assessment)
    verdict_label = _determine_verdict_label(total_severity)
    print(f"\n  ELA image: {ela['ela_image_saved']}")
    return verdict_label


def _build_report_data(
    image_path, basics, results, findings, total_severity, verdict_label, assessment
):
    """Build the complete report data dictionary for markdown generation.

    Args:
        image_path: Path to the image file.
        basics: Tuple of (width, height, format, mode).
        results: Dictionary of all analysis results.
        findings: List of (description, severity) tuples.
        total_severity: Total severity score.
        verdict_label: Verdict label string.

    Returns:
        Complete report data dictionary.
    """
    img_w, img_h, img_format, img_mode = basics
    d = {
        "filename": os.path.basename(image_path),
        "timestamp": datetime.datetime.now().strftime("%B %d, %Y at %H:%M"),
        "img_w": img_w,
        "img_h": img_h,
        "img_format": img_format,
        "img_mode": img_mode,
        "findings": findings,
        "total_severity": total_severity,
        "verdict_label": verdict_label,
        "assessment": assessment,
    }
    d.update(results)
    return d


def _save_markdown_report(report_data, image_path):
    """Generate and save the markdown report to disk.

    Args:
        report_data: Complete report data dictionary.
        image_path: Original image path (used to derive output path).

    Returns:
        Path to the saved markdown file.
    """
    md_report = _build_markdown_report(report_data)
    md_path = os.path.splitext(image_path)[0] + "_REPORT.md"
    with open(md_path, "w") as f:
        f.write(md_report)
    print(f"  Report:    {md_path}")
    return md_path


def _attempt_pdf_generation(md_path, image_path):
    """Attempt to generate a PDF report from the markdown file.

    Args:
        md_path: Path to the markdown report file.
        image_path: Original image path (used to derive PDF path).
    """
    try:
        from generate_pdf import _generate_pdf as make_pdf

        pdf_path = os.path.splitext(image_path)[0] + "_REPORT.pdf"
        make_pdf(md_path, pdf_path)
    except ImportError:
        print("  >> PDF generation requires: pip install 'pixelproof[pdf]'")
    except Exception as e:
        print(f"  >> PDF generation failed: {e}")


def _attempt_provenance_generation(image_path, md_path, ela_path, pdf_path=None):
    """Generate provenance manifest and optional detached signature.

    Args:
        image_path: Input image path.
        md_path: Markdown report path.
        ela_path: ELA artifact path.
        pdf_path: Optional PDF report path.
    """
    key = os.environ.get("PIXELPROOF_PROVENANCE_KEY")
    manifest_path, sig_path = create_provenance_bundle(
        image_path, md_path, ela_path, pdf_path, key
    )
    print(f"  Provenance: {manifest_path}")
    if sig_path:
        print(f"  Signature:  {sig_path}")


def _compute_forensic_assessment(results):
    """Compute findings, severity, and fused authenticity assessment.

    Args:
        results: Full analysis results dictionary.

    Returns:
        Tuple of (findings, total_severity, assessment).
    """
    findings, total_severity = _compute_all_findings(results)
    results["findings"] = findings
    assessment = compute_authenticity_assessment(results)
    return findings, total_severity, assessment


def _build_and_save_report(
    image_path,
    basics,
    results,
    findings,
    total_severity,
    verdict_label,
    assessment,
):
    """Build and save markdown report from analysis outputs.

    Args:
        image_path: Path to source image.
        basics: Basic image metadata tuple.
        results: Full analysis results dictionary.
        findings: Forensic findings list.
        total_severity: Total severity score.
        verdict_label: Final terminal verdict label.
        assessment: Fused authenticity assessment dictionary.

    Returns:
        Path to saved markdown report.
    """
    report_data = _build_report_data(
        image_path, basics, results, findings, total_severity, verdict_label, assessment
    )
    return _save_markdown_report(report_data, image_path)


def _report_pdf_path(image_path):
    """Derive PDF report path from image path.

    Args:
        image_path: Input image path.

    Returns:
        Expected PDF report path.
    """
    return os.path.splitext(image_path)[0] + "_REPORT.pdf"


def _full_forensic_analysis(
    image_path, generate_pdf_flag=False, generate_provenance=False
):
    """Run the complete forensic analysis pipeline on an image.

    Args:
        image_path: Path to the image file to analyze.
        generate_pdf_flag: Whether to generate a PDF report.
        generate_provenance: Whether to generate provenance artifacts.
    """
    _print_banner(image_path)
    basics = _get_image_basics(image_path)
    results = _run_all_analyses(image_path)
    findings, total_severity, assessment = _compute_forensic_assessment(results)
    verdict_label = _print_terminal_verdict(
        findings, total_severity, results["ela"], assessment
    )
    md_path = _build_and_save_report(
        image_path, basics, results, findings, total_severity, verdict_label, assessment
    )
    pdf_path = _report_pdf_path(image_path) if generate_pdf_flag else None
    if generate_pdf_flag:
        _attempt_pdf_generation(md_path, image_path)
    if generate_provenance:
        _attempt_provenance_generation(
            image_path, md_path, results["ela"]["ela_image_saved"], pdf_path
        )
    print("=" * 70)


# ===========================================================================
# CLI entry point
# ===========================================================================


def _parse_cli_args():
    """Parse command-line arguments for the deep analysis tool.

    Returns:
        Tuple of (image_path, want_pdf_bool, want_provenance_bool).
    """
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    if not args:
        print("Usage: python deep_analysis.py <image_path> [--pdf] [--provenance]")
        print("")
        print("  Runs 10-pass forensic analysis and saves:")
        print("    <image>_ELA.png     Error Level Analysis image")
        print("    <image>_REPORT.md   Comprehensive Markdown report")
        print("    <image>_REPORT.pdf  PDF report (with --pdf)")
        sys.exit(1)
    return args[0], "--pdf" in flags, "--provenance" in flags


def _validate_image_file(image_path):
    """Validate that the image file exists, exiting if not found.

    Args:
        image_path: Path to check.

    Returns:
        The validated image path.
    """
    if not os.path.isfile(image_path):
        print(f"Error: file not found -- {image_path}")
        sys.exit(1)
    return image_path


def main():
    """Entry point for the deep_analysis command-line tool."""
    image_path, want_pdf, want_provenance = _parse_cli_args()
    _validate_image_file(image_path)
    _full_forensic_analysis(
        image_path, generate_pdf_flag=want_pdf, generate_provenance=want_provenance
    )


if __name__ == "__main__":
    main()
