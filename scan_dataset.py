#!/usr/bin/env python3
"""
XAI-IDPS-SOC Dataset & File Type Signature Scanner.

Scans the data/ directory recursively, detects real file signatures via magic bytes,
identifies non-UTF-8 text encodings and converts them cleanly to UTF-8, catalogs
genuinely binary files (PCAP, Joblib models, ZIP, SQLite, etc.) with recommended
opening tools, and generates dataset_scan_report.csv.
"""

import argparse
import csv
import io
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import charset_normalizer
except ImportError:
    charset_normalizer = None

try:
    import chardet
except ImportError:
    chardet = None


# Magic byte signatures mapped to (detected_type, recommended_tool)
MAGIC_SIGNATURES: List[Tuple[bytes, str, str]] = [
    # PCAP / PCAPNG network packet captures
    (b"\xd4\xc3\xb2\xa1", "genuinely binary (pcap little-endian)", "Wireshark / tcpdump / tshark"),
    (b"\xa1\xb2\xc3\xd4", "genuinely binary (pcap big-endian)", "Wireshark / tcpdump / tshark"),
    (b"\x4d\x3c\xb2\xa1", "genuinely binary (pcap nanosecond LE)", "Wireshark / tcpdump / tshark"),
    (b"\xa1\xb2\x3c\x4d", "genuinely binary (pcap nanosecond BE)", "Wireshark / tcpdump / tshark"),
    (b"\x0a\x0d\x0d\x0a", "genuinely binary (pcapng capture)", "Wireshark / tcpdump / tshark"),
    # SQLite Database
    (b"SQLite format 3\x00", "genuinely binary (sqlite database)", "sqlite3 / DB Browser for SQLite"),
    # Apache Parquet
    (b"PAR1", "genuinely binary (parquet dataset)", "Python (pandas.read_parquet) / DuckDB"),
    # HDF5 / Keras Neural Net Weights
    (b"\x89HDF\r\n\x1a\n", "genuinely binary (hdf5 / keras model)", "Python (h5py / keras.models.load_model)"),
    # PDF
    (b"%PDF-", "genuinely binary (pdf document)", "Adobe Acrobat / Preview / PDF Viewer"),
    # 7-Zip Archive
    (b"7z\xbc\xaf\x27\x1c", "genuinely binary (7z archive)", "7z / p7zip / Archive Utility"),
    # GZIP (frequently used for compressed models/pcaps)
    (b"\x1f\x8b", "genuinely binary (gzip archive)", "gzip -d / gunzip / tar -xzf"),
    # BZIP2
    (b"BZh", "genuinely binary (bzip2 archive)", "bzip2 -d / tar -xjf"),
    # Python Pickle / Joblib protocols
    (b"\x80\x02", "genuinely binary (joblib/pickle protocol 2)", "Python (joblib.load / pickle.load)"),
    (b"\x80\x03", "genuinely binary (joblib/pickle protocol 3)", "Python (joblib.load / pickle.load)"),
    (b"\x80\x04", "genuinely binary (joblib/pickle protocol 4)", "Python (joblib.load / pickle.load)"),
    (b"\x80\x05", "genuinely binary (joblib/pickle protocol 5)", "Python (joblib.load / pickle.load)"),
    (b"\x93NUMPY", "genuinely binary (numpy array binary)", "Python (numpy.load)"),
    # Mach-O / ELF / PE Executables
    (b"\xfe\xed\xfa\xce", "genuinely binary (mach-o 32-bit)", "otool / Hopper / Ghidra"),
    (b"\xfe\xed\xfa\xcf", "genuinely binary (mach-o 64-bit)", "otool / Hopper / Ghidra"),
    (b"\xcf\xfa\xed\xfe", "genuinely binary (mach-o 64-bit LE)", "otool / Hopper / Ghidra"),
    (b"\xca\xfe\xba\xbe", "genuinely binary (mach-o fat / java class)", "otool / javap / Ghidra"),
    (b"\x7fELF", "genuinely binary (elf executable)", "readelf / objdump / Ghidra"),
    (b"MZ", "genuinely binary (windows pe / exe / dll)", "PEview / Ghidra"),
]


def detect_encoding(raw_bytes: bytes) -> Optional[str]:
    """Detect non-UTF8 encoding using charset_normalizer or chardet."""
    if charset_normalizer is not None:
        try:
            best = charset_normalizer.from_bytes(raw_bytes).best()
            if best and best.encoding:
                return best.encoding
        except Exception:
            pass

    if chardet is not None:
        try:
            res = chardet.detect(raw_bytes[:65536])
            if res and res.get("encoding"):
                return res["encoding"]
        except Exception:
            pass

    # Common fallback candidates
    for enc in ["latin-1", "cp1252", "iso-8859-1", "utf-16"]:
        try:
            raw_bytes.decode(enc)
            return enc
        except Exception:
            continue

    return None


def inspect_file(filepath: Path) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """
    Inspect real file type using signature/magic bytes and encoding checks.

    Returns:
        (category, detected_type, recommended_tool, detected_encoding)
        where category is:
          - 'proper_csv_text'
          - 'wrong_encoding_text'
          - 'genuinely_binary'
    """
    size = filepath.stat().st_size
    if size == 0:
        return ("proper_csv_text", "proper CSV/text (empty file)", None, "utf-8")

    # Read leading bytes for magic signature checks
    with open(filepath, "rb") as f:
        header = f.read(4096)

    # 1. Check ZIP-based files (PK\x03\x04, PK\x05\x06, PK\x07\x08)
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                names = zf.namelist()
                if any("xl/" in n or "workbook.xml" in n for n in names):
                    return ("genuinely_binary", "genuinely binary (xlsx spreadsheet)", "Microsoft Excel / LibreOffice / pandas.read_excel", None)
                if any("word/" in n for n in names):
                    return ("genuinely_binary", "genuinely binary (docx document)", "Microsoft Word / LibreOffice", None)
                if any("data.pkl" in n or "byteorder" in n for n in names):
                    return ("genuinely_binary", "genuinely binary (pytorch model)", "Python (torch.load)", None)
                if any(n.endswith(".joblib") for n in names):
                    return ("genuinely_binary", "genuinely binary (joblib archive)", "Python (joblib.load)", None)
                return ("genuinely_binary", "genuinely binary (zip archive)", "unzip / 7-Zip / Archive Utility", None)
        except Exception:
            return ("genuinely_binary", "genuinely binary (zip archive)", "unzip / 7-Zip / Archive Utility", None)

    # 2. Check TAR archives
    if len(header) > 262 and header[257:262] == b"ustar":
        return ("genuinely_binary", "genuinely binary (tar archive)", "tar -xvf / 7-Zip", None)

    # 3. Check known magic byte signatures
    for sig, sig_type, tool in MAGIC_SIGNATURES:
        if header.startswith(sig):
            # Check if this GZIP is actually a compressed model or pcap
            if sig == b"\x1f\x8b":
                stem_ext = filepath.name.lower()
                if "joblib" in stem_ext or "model" in stem_ext:
                    return ("genuinely_binary", "genuinely binary (joblib model - gzip compressed)", "Python (joblib.load)", None)
                if "pcap" in stem_ext:
                    return ("genuinely_binary", "genuinely binary (pcap.gz capture)", "Wireshark / zcat / tcpdump", None)
            return ("genuinely_binary", sig_type, tool, None)

    # 4. Check for UTF-16 / UTF-32 BOMs
    if header.startswith(b"\xff\xfe\x00\x00") or header.startswith(b"\x00\x00\xfe\xff"):
        return ("wrong_encoding_text", "wrong-encoding text (utf-32 BOM)", None, "utf-32")
    if header.startswith(b"\xff\xfe"):
        return ("wrong_encoding_text", "wrong-encoding text (utf-16-le BOM)", None, "utf-16-le")
    if header.startswith(b"\xfe\xff"):
        return ("wrong_encoding_text", "wrong-encoding text (utf-16-be BOM)", None, "utf-16-be")

    # 5. Read a sample or full content to test text decodability
    # For large files (>20MB), sample up to 2MB; for smaller files, inspect entirely
    sample_size = min(size, 2 * 1024 * 1024)
    with open(filepath, "rb") as f:
        sample_bytes = f.read(sample_size)

    # Check for binary null bytes
    if b"\x00" in sample_bytes:
        # Null bytes in plain text without UTF-16 BOM almost always denote raw binary
        # Check if it has a high concentration of joblib/pickle strings
        if b"sklearn" in sample_bytes or b"numpy" in sample_bytes or b"xgboost" in sample_bytes:
            return ("genuinely_binary", "genuinely binary (joblib/pickle ml model)", "Python (joblib.load)", None)
        return ("genuinely_binary", "genuinely binary (unknown binary format)", "Hex Editor / file command", None)

    # 6. Test strict UTF-8 decoding
    try:
        sample_bytes.decode("utf-8")
        # Test full file if sampled
        if sample_size < size:
            with open(filepath, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    chunk.decode("utf-8")
        return ("proper_csv_text", "proper CSV/text (utf-8)", None, "utf-8")
    except UnicodeDecodeError:
        pass

    # 7. File is text but NOT UTF-8: detect encoding
    detected_enc = detect_encoding(sample_bytes)
    if detected_enc:
        return ("wrong_encoding_text", f"wrong-encoding text ({detected_enc})", None, detected_enc)

    return ("genuinely_binary", "genuinely binary (undecodable byte sequence)", "Hex Editor / file command", None)


def convert_file_to_utf8(src_path: Path, dst_path: Path, encoding: str) -> None:
    """Read file with detected encoding and write to destination as clean UTF-8."""
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with open(src_path, "r", encoding=encoding, errors="replace") as fin:
        content = fin.read()
    # Strip leading Byte Order Mark (BOM) so VS Code and pandas read clean header names
    if content.startswith("\ufeff"):
        content = content[1:]
    with open(dst_path, "w", encoding="utf-8") as fout:
        fout.write(content)


def scan_and_process(
    root_dir: Path,
    report_csv_path: Path,
    clean_dir: Optional[Path] = None,
    in_place: bool = False,
) -> None:
    """Walk root_dir, classify files, convert text to UTF-8, and generate report."""
    print("=" * 80)
    print("🔍  XAI-IDPS-SOC DATASET SCANNER & SIGNATURE ENCODING AUDIT")
    print("=" * 80)
    print(f"Target Directory: {root_dir.resolve()}")
    if in_place:
        print("Conversion Mode:  IN-PLACE (re-encoding wrong-encoding text files to UTF-8)")
    elif clean_dir:
        print(f"Conversion Mode:  MIRROR PRESERVATION -> {clean_dir.resolve()}")
    print(f"Report CSV Path:  {report_csv_path.resolve()}\n")

    results: List[Dict[str, str]] = []
    binary_files: List[Dict[str, str]] = []
    failed_files: List[Tuple[str, str]] = []

    count_fine = 0
    count_converted = 0
    count_binary = 0

    # Gather all files
    all_files: List[Path] = [p for p in root_dir.rglob("*") if p.is_file() and not p.name.startswith(".DS_Store")]
    all_files.sort()

    if not all_files:
        print(f"⚠️  No files found under {root_dir}. Please check directory path.")
        return

    print(f"Discovered {len(all_files)} total files under '{root_dir}'. Analyzing magic bytes...")
    print("-" * 80)

    for idx, filepath in enumerate(all_files, 1):
        rel_path = filepath.relative_to(root_dir)
        try:
            category, detected_type, tool, detected_enc = inspect_file(filepath)

            if category == "proper_csv_text":
                count_fine += 1
                action_taken = "already_utf8 (no action needed)"
                if clean_dir and not in_place:
                    # Mirror clean file
                    mirror_target = clean_dir / rel_path
                    mirror_target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(filepath, mirror_target)

            elif category == "wrong_encoding_text":
                enc = detected_enc or "latin-1"
                if in_place:
                    # Convert in-place (with backup temp)
                    temp_file = filepath.with_suffix(filepath.suffix + ".tmp_utf8")
                    convert_file_to_utf8(filepath, temp_file, enc)
                    temp_file.replace(filepath)
                    action_taken = f"converted_to_utf8_in_place (from {enc} to UTF-8)"
                else:
                    target_dest = (clean_dir / rel_path) if clean_dir else (root_dir / f"{filepath.stem}_utf8{filepath.suffix}")
                    convert_file_to_utf8(filepath, target_dest, enc)
                    action_taken = f"converted_to_utf8 (from {enc} -> {target_dest.name})"
                count_converted += 1

            else:  # genuinely_binary
                count_binary += 1
                action_taken = f"skipped (binary file - open with {tool or 'Specialized Tool'})"
                binary_files.append({
                    "filename": str(rel_path),
                    "detected_type": detected_type,
                    "tool": tool or "Hex Editor / file",
                })
                if clean_dir and not in_place:
                    # Mirror binary file so data_clean is a complete replica
                    mirror_target = clean_dir / rel_path
                    mirror_target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(filepath, mirror_target)

            results.append({
                "filepath": str(filepath),
                "detected_type": detected_type,
                "action_taken": action_taken,
            })

            # Real-time console line
            status_tag = "✓ UTF-8 " if category == "proper_csv_text" else ("⚡ CONV " if category == "wrong_encoding_text" else "📦 BIN  ")
            print(f"[{status_tag}] {str(rel_path):<50} | {detected_type}")

        except Exception as ex:
            error_msg = f"Failed to process: {str(ex)}"
            failed_files.append((str(filepath), str(ex)))
            results.append({
                "filepath": str(filepath),
                "detected_type": "error_inspecting",
                "action_taken": f"error: {str(ex)}",
            })
            print(f"[❌ ERR ] {str(rel_path):<50} | {error_msg}")

    # Write report CSV
    report_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["filepath", "detected_type", "action_taken"])
        writer.writeheader()
        writer.writerows(results)

    # Print Summary Tables & Final Report
    print("\n" + "=" * 80)
    print("📦  GENUINELY BINARY FILES SUMMARY TABLE (Specialized Tools Required)")
    print("=" * 80)
    if binary_files:
        print(f"{'Filename / Path':<45} | {'Detected Signature':<24} | {'Recommended Tool'}")
        print("-" * 80)
        for b in binary_files:
            fn_display = b["filename"]
            if len(fn_display) > 43:
                fn_display = "..." + fn_display[-40:]
            print(f"{fn_display:<45} | {b['detected_type']:<24} | {b['tool']}")
    else:
        print("No binary files detected in scanned directory.")

    print("\n" + "=" * 80)
    print("📊  FINAL SCAN & ENCODING AUDIT REPORT")
    print("=" * 80)
    print(f"  • Total files analyzed:                   {len(all_files)}")
    print(f"  • Proper CSV / UTF-8 text (already fine):  {count_fine}")
    print(f"  • Wrong-encoding text (converted):        {count_converted}")
    print(f"  • Genuinely binary files (preserved):     {count_binary}")
    print(f"  • Processing failures / errors:           {len(failed_files)}")
    print("-" * 80)
    print(f"📁 Scan report written to: {report_csv_path.resolve()}")
    if clean_dir and not in_place:
        print(f"📁 Clean mirrored files in: {clean_dir.resolve()}")
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Scan data/ folder, detect real file signatures via magic bytes, and fix encodings."
    )
    parser.add_argument(
        "--root",
        default="data",
        help="Root folder to scan recursively (default: 'data').",
    )
    parser.add_argument(
        "--report",
        default="dataset_scan_report.csv",
        help="Output CSV report path (default: 'dataset_scan_report.csv').",
    )
    parser.add_argument(
        "--clean-dir",
        default="data_clean",
        help="Mirror folder where converted UTF-8 files and clean copies are saved (default: 'data_clean').",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Convert wrong-encoding text files directly in-place instead of mirroring to clean-dir.",
    )

    args = parser.parse_args()

    root_path = Path(args.root)
    # Fallback to detection/data if data doesn't exist
    if not root_path.exists():
        fallback = Path("detection/data")
        if fallback.exists():
            print(f"Notice: '{root_path}' not found at current location. Using fallback '{fallback}'.")
            root_path = fallback
        else:
            sys.exit(f"Error: Target directory '{root_path}' does not exist.")

    report_path = Path(args.report)
    clean_path = Path(args.clean_dir) if not args.in_place else None

    scan_and_process(
        root_dir=root_path,
        report_csv_path=report_path,
        clean_dir=clean_path,
        in_place=args.in_place,
    )


if __name__ == "__main__":
    main()
