#!/usr/bin/env python3
"""Create and verify provenance manifests for PixelProof artifacts."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import sys


def _read_bytes(path):
    """Read raw bytes from file.

    Args:
        path: File path.

    Returns:
        Raw file bytes.
    """
    with open(path, "rb") as handle:
        return handle.read()


def _read_json(path):
    """Read JSON document from file.

    Args:
        path: File path.

    Returns:
        Parsed JSON dictionary.
    """
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path, payload):
    """Write JSON payload to file.

    Args:
        path: File path.
        payload: JSON-serializable object.
    """
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def _write_text(path, text):
    """Write UTF-8 text line to file.

    Args:
        path: File path.
        text: Text content.
    """
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text + "\n")


def _sha256_bytes(data):
    """Compute SHA-256 digest for raw bytes.

    Args:
        data: Input bytes.

    Returns:
        Hex digest string.
    """
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    """Compute SHA-256 digest for file.

    Args:
        path: File path.

    Returns:
        Hex digest string.
    """
    return _sha256_bytes(_read_bytes(path))


def _hmac_hex(data, key):
    """Compute HMAC-SHA256 signature hex.

    Args:
        data: Input bytes.
        key: Secret key string.

    Returns:
        Hex HMAC digest string.
    """
    return hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()


def _utc_timestamp():
    """Create UTC timestamp in ISO format.

    Returns:
        ISO-8601 UTC timestamp string.
    """
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _manifest_path(image_path):
    """Build manifest path from image path.

    Args:
        image_path: Source image path.

    Returns:
        Manifest JSON path.
    """
    return os.path.splitext(image_path)[0] + "_PROVENANCE.json"


def _signature_path(manifest_path):
    """Build signature path from manifest path.

    Args:
        manifest_path: Manifest JSON path.

    Returns:
        Detached signature path.
    """
    return manifest_path + ".sig"


def _canonical_manifest_bytes(manifest):
    """Serialize manifest into canonical bytes.

    Args:
        manifest: Manifest dictionary.

    Returns:
        Canonical JSON bytes.
    """
    text = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return text.encode("utf-8")


def _base_artifact_hashes(image_path, md_path, ela_path):
    """Build required artifact hashes.

    Args:
        image_path: Source image path.
        md_path: Markdown report path.
        ela_path: ELA artifact path.

    Returns:
        Required artifact hash dictionary.
    """
    return {
        "image_sha256": _sha256_file(image_path),
        "report_md_sha256": _sha256_file(md_path),
        "ela_sha256": _sha256_file(ela_path),
    }


def _with_pdf_hash(hashes, pdf_path):
    """Add optional PDF hash entry.

    Args:
        hashes: Mutable artifact hash dictionary.
        pdf_path: Optional PDF path.

    Returns:
        Updated artifact hash dictionary.
    """
    if pdf_path and os.path.isfile(pdf_path):
        hashes["report_pdf_sha256"] = _sha256_file(pdf_path)
    return hashes


def _artifact_hashes(image_path, md_path, ela_path, pdf_path=None):
    """Build full artifact hash mapping.

    Args:
        image_path: Source image path.
        md_path: Markdown report path.
        ela_path: ELA artifact path.
        pdf_path: Optional PDF report path.

    Returns:
        Full artifact hash dictionary.
    """
    hashes = _base_artifact_hashes(image_path, md_path, ela_path)
    return _with_pdf_hash(hashes, pdf_path)


def _manifest_payload(image_path, md_path, ela_path, pdf_path=None):
    """Build provenance manifest payload.

    Args:
        image_path: Source image path.
        md_path: Markdown report path.
        ela_path: ELA artifact path.
        pdf_path: Optional PDF report path.

    Returns:
        Manifest dictionary payload.
    """
    artifacts = _artifact_hashes(image_path, md_path, ela_path, pdf_path)
    return {
        "schema": "pixelproof.provenance.v1",
        "generated_utc": _utc_timestamp(),
        "image": os.path.basename(image_path),
        "artifacts": artifacts,
    }


def _create_unsigned_bundle(image_path, md_path, ela_path, pdf_path=None):
    """Create manifest file without signature.

    Args:
        image_path: Source image path.
        md_path: Markdown report path.
        ela_path: ELA artifact path.
        pdf_path: Optional PDF report path.

    Returns:
        Tuple of (manifest_path, manifest_payload).
    """
    manifest = _manifest_payload(image_path, md_path, ela_path, pdf_path)
    manifest_path = _manifest_path(image_path)
    _write_json(manifest_path, manifest)
    return manifest_path, manifest


def _create_signed_bundle(manifest_path, manifest, signing_key):
    """Create detached signature for manifest.

    Args:
        manifest_path: Manifest JSON path.
        manifest: Manifest dictionary payload.
        signing_key: HMAC signing key string.

    Returns:
        Signature path.
    """
    sig_path = _signature_path(manifest_path)
    digest = _hmac_hex(_canonical_manifest_bytes(manifest), signing_key)
    _write_text(sig_path, digest)
    return sig_path


def _create_provenance_bundle(
    image_path, md_path, ela_path, pdf_path=None, signing_key=None
):
    """Create provenance bundle with optional signature.

    Args:
        image_path: Source image path.
        md_path: Markdown report path.
        ela_path: ELA artifact path.
        pdf_path: Optional PDF report path.
        signing_key: Optional HMAC signing key.

    Returns:
        Tuple of (manifest_path, signature_path_or_none).
    """
    manifest_path, manifest = _create_unsigned_bundle(
        image_path, md_path, ela_path, pdf_path
    )
    if not signing_key:
        return manifest_path, None
    sig_path = _create_signed_bundle(manifest_path, manifest, signing_key)
    return manifest_path, sig_path


def create_provenance_bundle(
    image_path, md_path, ela_path, pdf_path=None, signing_key=None
):
    """Public wrapper to create provenance artifacts.

    Args:
        image_path: Source image path.
        md_path: Markdown report path.
        ela_path: ELA artifact path.
        pdf_path: Optional PDF report path.
        signing_key: Optional HMAC signing key.

    Returns:
        Tuple of (manifest_path, signature_path_or_none).
    """
    return _create_provenance_bundle(
        image_path, md_path, ela_path, pdf_path, signing_key
    )


def _hash_check(name, expected, actual):
    """Build one hash check result tuple.

    Args:
        name: Artifact hash label.
        expected: Expected digest string.
        actual: Recomputed digest string.

    Returns:
        Tuple of (ok_bool, message).
    """
    ok = expected == actual
    return ok, f"{name}: {'OK' if ok else 'MISMATCH'}"


def _artifact_checks(expected, actual):
    """Build hash checks for all available artifacts.

    Args:
        expected: Expected artifact hash dictionary.
        actual: Recomputed artifact hash dictionary.

    Returns:
        List of (ok_bool, message) tuples.
    """
    names = sorted(actual)
    return [
        _hash_check(name, expected.get(name, ""), actual.get(name, ""))
        for name in names
    ]


def _signature_check(manifest, sig_path, signing_key):
    """Verify detached signature when provided.

    Args:
        manifest: Manifest dictionary.
        sig_path: Optional signature path.
        signing_key: Optional signing key.

    Returns:
        Tuple of (ok_bool, message).
    """
    if not (sig_path and signing_key and os.path.isfile(sig_path)):
        return True, "signature: SKIPPED"
    expected = _read_bytes(sig_path).decode("utf-8").strip()
    actual = _hmac_hex(_canonical_manifest_bytes(manifest), signing_key)
    return _hash_check("signature", expected, actual)


def _verify_provenance_bundle(
    image_path,
    md_path,
    ela_path,
    manifest_path,
    pdf_path=None,
    sig_path=None,
    signing_key=None,
):
    """Verify provenance bundle hashes and optional signature.

    Args:
        image_path: Source image path.
        md_path: Markdown report path.
        ela_path: ELA artifact path.
        manifest_path: Manifest JSON path.
        pdf_path: Optional PDF report path.
        sig_path: Optional detached signature path.
        signing_key: Optional HMAC signing key.

    Returns:
        Tuple of (all_ok_bool, messages_list).
    """
    manifest = _read_json(manifest_path)
    expected = manifest.get("artifacts", {})
    actual = _artifact_hashes(image_path, md_path, ela_path, pdf_path)
    checks = _artifact_checks(expected, actual)
    checks.append(_signature_check(manifest, sig_path, signing_key))
    return all(ok for ok, _ in checks), [msg for _, msg in checks]


def verify_provenance_bundle(
    image_path,
    md_path,
    ela_path,
    manifest_path,
    pdf_path=None,
    sig_path=None,
    signing_key=None,
):
    """Public wrapper to verify provenance bundle.

    Args:
        image_path: Source image path.
        md_path: Markdown report path.
        ela_path: ELA artifact path.
        manifest_path: Manifest JSON path.
        pdf_path: Optional PDF report path.
        sig_path: Optional detached signature path.
        signing_key: Optional HMAC signing key.

    Returns:
        Tuple of (all_ok_bool, messages_list).
    """
    return _verify_provenance_bundle(
        image_path, md_path, ela_path, manifest_path, pdf_path, sig_path, signing_key
    )


def _usage_lines():
    """Return CLI usage lines for provenance utility.

    Returns:
        List of usage lines.
    """
    return [
        "Usage:",
        "  python provenance.py create <image> <report.md> <ela.png> [report.pdf]",
        "  python provenance.py verify <image> <report.md> <ela.png> <manifest.json> [report.pdf] [manifest.sig]",
        "",
        "Optional signing key:",
        "  PIXELPROOF_PROVENANCE_KEY=<secret>",
    ]


def _print_usage():
    """Print usage and terminate process.

    Raises:
        SystemExit: Always exits with status code 1.
    """
    for line in _usage_lines():
        print(line)
    raise SystemExit(1)


def _create_cli(args, key):
    """Handle create subcommand for provenance CLI.

    Args:
        args: Positional args after create.
        key: Optional signing key string.
    """
    if len(args) < 3:
        _print_usage()
    pdf_path = args[3] if len(args) > 3 else None
    manifest_path, sig_path = _create_provenance_bundle(
        args[0], args[1], args[2], pdf_path, key
    )
    print(f"manifest: {manifest_path}")
    print(f"signature: {sig_path or 'none'}")


def _verify_cli(args, key):
    """Handle verify subcommand for provenance CLI.

    Args:
        args: Positional args after verify.
        key: Optional signing key string.

    Raises:
        SystemExit: Exits with status code 2 on failure.
    """
    if len(args) < 4:
        _print_usage()
    pdf_path = args[4] if len(args) > 4 else None
    sig_path = args[5] if len(args) > 5 else None
    ok, messages = _verify_provenance_bundle(
        args[0], args[1], args[2], args[3], pdf_path, sig_path, key
    )
    for msg in messages:
        print(msg)
    if not ok:
        raise SystemExit(2)


def provenance_main(argv=None):
    """Run provenance command-line interface.

    Args:
        argv: Optional argument list.

    Returns:
        Process exit code.
    """
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        _print_usage()
    key = os.environ.get("PIXELPROOF_PROVENANCE_KEY")
    cmd, rest = args[0], args[1:]
    if cmd == "create":
        _create_cli(rest, key)
    elif cmd == "verify":
        _verify_cli(rest, key)
    else:
        _print_usage()
    return 0


if __name__ == "__main__":
    raise SystemExit(provenance_main())
