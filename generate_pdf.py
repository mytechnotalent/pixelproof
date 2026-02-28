#!/usr/bin/env python3
"""
pixelproof pdf -- Generate a professional PDF report from a Markdown file.

Usage:
    python generate_pdf.py <markdown_file> [output.pdf]

Requires:
    pip install markdown2 weasyprint
    brew install pango  (macOS)
"""

import sys
import os
import markdown2

# ---------------------------------------------------------------------------
# CSS stylesheet constant for forensic report PDF styling
# ---------------------------------------------------------------------------

PDF_CSS = """
@page {
    size: letter;
    margin: 0.75in 0.85in;
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9px;
        color: #888;
        font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    }
    @top-center {
        content: "PIXELPROOF FORENSIC REPORT";
        font-size: 8px;
        color: #aaa;
        font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
        letter-spacing: 2px;
        text-transform: uppercase;
    }
}
body {
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 11px; line-height: 1.6; color: #1a1a1a;
}
h1 {
    font-size: 22px; font-weight: 700; color: #111;
    border-bottom: 3px solid #c0392b; padding-bottom: 8px; margin-top: 0;
}
h2 {
    font-size: 16px; font-weight: 700; color: #2c3e50;
    border-bottom: 1.5px solid #bdc3c7; padding-bottom: 5px;
    margin-top: 28px; page-break-after: avoid;
}
h3 {
    font-size: 13px; font-weight: 700; color: #34495e;
    margin-top: 18px; page-break-after: avoid;
}
h4 {
    font-size: 12px; font-weight: 700; color: #555;
    margin-top: 14px; page-break-after: avoid;
}
p { margin: 6px 0; }
strong { color: #111; }
blockquote {
    border-left: 4px solid #c0392b; background: #fdf2f2;
    padding: 10px 14px; margin: 12px 0; font-style: normal; color: #333;
}
table {
    width: 100%; border-collapse: collapse; margin: 10px 0;
    font-size: 10px; page-break-inside: avoid;
}
th {
    background: #2c3e50; color: white; font-weight: 600;
    text-align: left; padding: 6px 8px; font-size: 10px;
}
td {
    padding: 5px 8px; border-bottom: 1px solid #ddd; vertical-align: top;
}
tr:nth-child(even) { background: #f7f9fa; }
code {
    background: #f4f4f4; padding: 1px 4px; border-radius: 3px;
    font-family: 'Menlo', 'Courier New', monospace; font-size: 10px;
    color: #c0392b;
}
pre {
    background: #1e1e1e; color: #d4d4d4; padding: 12px 14px;
    border-radius: 4px; font-family: 'Menlo', 'Courier New', monospace;
    font-size: 9.5px; line-height: 1.5; page-break-inside: avoid;
}
pre code { background: none; color: #d4d4d4; padding: 0; }
hr { border: none; border-top: 1px solid #ccc; margin: 20px 0; }
ul, ol { margin: 6px 0; padding-left: 24px; }
li { margin: 3px 0; }
"""


# ---------------------------------------------------------------------------
# Private helpers for _generate_pdf (in call order)
# ---------------------------------------------------------------------------


def _default_pdf_path(md_path):
    """Derive the default PDF output path from a Markdown file path.

    Args:
        md_path: Path to the source Markdown file.

    Returns:
        PDF path with the same basename and .pdf extension.
    """
    return os.path.splitext(md_path)[0] + ".pdf"


def _read_markdown(md_path):
    """Read and return the full contents of a Markdown file.

    Args:
        md_path: Path to the Markdown file.

    Returns:
        The file contents as a string.
    """
    with open(md_path, "r") as f:
        return f.read()


def _convert_to_html(md_content):
    """Convert Markdown text to HTML with table and code block support.

    Args:
        md_content: Markdown-formatted string.

    Returns:
        HTML string of the converted content.
    """
    return markdown2.markdown(
        md_content,
        extras=["tables", "fenced-code-blocks", "code-friendly", "break-on-newline"],
    )


def _build_html_document(html_body):
    """Wrap an HTML body fragment into a full HTML document with PDF CSS.

    Args:
        html_body: HTML content string for the document body.

    Returns:
        Complete HTML document string with embedded CSS.
    """
    return (
        f'<!DOCTYPE html>\n<html><head><meta charset="utf-8">'
        f"<style>{PDF_CSS}</style></head>\n<body>{html_body}</body></html>"
    )


def _write_pdf_file(html_doc, pdf_path):
    """Render an HTML document to a PDF file using WeasyPrint.

    Args:
        html_doc: Complete HTML document string.
        pdf_path: Output file path for the PDF.
    """
    from weasyprint import HTML

    HTML(string=html_doc).write_pdf(pdf_path)


def _print_pdf_result(pdf_path):
    """Print a confirmation message with the PDF path and file size.

    Args:
        pdf_path: Path to the generated PDF file.
    """
    size_kb = os.path.getsize(pdf_path) / 1024
    print(f"\u2713 PDF generated: {pdf_path} ({size_kb:.1f} KB)")


def _generate_pdf(md_path, pdf_path=None):
    """Convert a Markdown file to a styled forensic report PDF.

    Args:
        md_path: Path to the input Markdown file.
        pdf_path: Optional output PDF path; defaults to same basename.

    Returns:
        The path to the generated PDF file.
    """
    pdf_path = pdf_path or _default_pdf_path(md_path)
    md_content = _read_markdown(md_path)
    html_body = _convert_to_html(md_content)
    html_doc = _build_html_document(html_body)
    _write_pdf_file(html_doc, pdf_path)
    _print_pdf_result(pdf_path)
    return pdf_path


# ---------------------------------------------------------------------------
# Private helpers for main (in call order)
# ---------------------------------------------------------------------------


def _validate_cli_args():
    """Validate CLI arguments and return Markdown path and optional PDF path.

    Returns:
        Tuple of (md_path, pdf_path) where pdf_path may be None.
    """
    if len(sys.argv) < 2:
        print("Usage: python generate_pdf.py <markdown_file> [output.pdf]")
        sys.exit(1)
    md_path = sys.argv[1]
    pdf_path = sys.argv[2] if len(sys.argv) > 2 else None
    if not os.path.isfile(md_path):
        print(f"Error: file not found -- {md_path}")
        sys.exit(1)
    return md_path, pdf_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main():
    """Entry point for the generate_pdf command-line tool."""
    md_path, pdf_path = _validate_cli_args()
    _generate_pdf(md_path, pdf_path)


if __name__ == "__main__":
    main()
