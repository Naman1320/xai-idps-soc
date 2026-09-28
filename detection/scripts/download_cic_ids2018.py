#!/usr/bin/env python3
"""
Download CSE-CIC-IDS2018 dataset from AWS Open Data.

Dataset: CSE-CIC-IDS2018
Source:  AWS Open Data Registry — s3://cse-cic-ids2018/
License: Open data, citation required
Signup:  None — no AWS account needed (--no-sign-request)

The dataset contains ~16M network flow instances collected over 10 days,
covering 7 attack scenarios: Brute-force, Heartbleed, Botnet, DoS, DDoS,
Web attacks, and infiltration.

Citation:
    Communications Security Establishment (CSE) & Canadian Institute for
    Cybersecurity (CIC). "A Realistic Cyber Defense Dataset (CSE-CIC-IDS2018)."
    https://registry.opendata.aws/cse-cic-ids2018/

Usage:
    # List available files
    python scripts/download_cic_ids2018.py --list

    # Download all days (~8 GB)
    python scripts/download_cic_ids2018.py

    # Download specific days only (lighter testing)
    python scripts/download_cic_ids2018.py --days wednesday thursday friday

    # Download to custom directory
    python scripts/download_cic_ids2018.py --output-dir /path/to/data
"""

import argparse
import logging
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

S3_BUCKET = "s3://cse-cic-ids2018/"
DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "data" / "raw" / "cse-cic-ids2018"

# CSE-CIC-IDS2018 directory structure on S3
# The processed traffic CSV files are under Processed Traffic Data for ML Algorithms/
S3_PROCESSED_PREFIX = "Processed Traffic Data for ML Algorithms/"

# Known CSV files in the dataset (by day/attack scenario)
KNOWN_FILES = {
    "wednesday": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "thursday-1": "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "friday-1": "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "tuesday": "Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
    "wednesday-2": "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "thursday-2": "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    "friday-2": "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "wednesday-3": "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    "thursday-3": "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    "friday-3": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
}

# Attack scenarios by day (for reference)
DAY_DESCRIPTIONS = {
    "wednesday": "Wed 14-Feb: Brute Force (FTP, SSH)",
    "thursday-1": "Thu 15-Feb: DoS (Hulk, SlowHTTPTest, Slowloris, GoldenEye)",
    "friday-1": "Fri 16-Feb: DoS (Hulk, SlowHTTPTest, Slowloris, GoldenEye), DDoS (LOIC-HTTP)",
    "tuesday": "Tue 20-Feb: DDoS (LOIC-UDP, LOIC-HTTP, HOIC)",
    "wednesday-2": "Wed 21-Feb: DDoS (LOIC-UDP, HOIC)",
    "thursday-2": "Thu 22-Feb: Brute Force (Web, XSS), SQL Injection",
    "friday-2": "Fri 23-Feb: Brute Force (Web, XSS), SQL Injection",
    "wednesday-3": "Wed 28-Feb: Infiltration",
    "thursday-3": "Thu 01-Mar: Infiltration",
    "friday-3": "Fri 02-Mar: Botnet (ARES)",
}


def check_aws_cli():
    """Check if AWS CLI is available."""
    try:
        result = subprocess.run(
            ["aws", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            logger.info(f"AWS CLI found: {result.stdout.strip()}")
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    logger.error(
        "AWS CLI not found. Install it with:\n"
        "  macOS:   brew install awscli\n"
        "  pip:     pip install awscli\n"
        "  Linux:   sudo apt install awscli"
    )
    return False


def list_s3_files():
    """List files in the S3 bucket."""
    logger.info("Listing files in s3://cse-cic-ids2018/...")
    try:
        result = subprocess.run(
            ["aws", "s3", "ls", "--no-sign-request", "--recursive", S3_BUCKET],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            print(result.stdout)
        else:
            logger.error(f"Failed to list S3 bucket: {result.stderr}")
    except subprocess.TimeoutExpired:
        logger.error("S3 listing timed out")


def download_file(s3_key: str, output_dir: Path) -> bool:
    """Download a single file from S3."""
    s3_path = f"{S3_BUCKET}{s3_key}"
    local_path = output_dir / Path(s3_key).name

    if local_path.exists():
        size_mb = local_path.stat().st_size / (1024 * 1024)
        logger.info(f"Already exists ({size_mb:.1f} MB): {local_path.name}")
        return True

    logger.info(f"Downloading: {s3_key} → {local_path}")
    try:
        result = subprocess.run(
            ["aws", "s3", "cp", "--no-sign-request", s3_path, str(local_path)],
            capture_output=False,
            timeout=3600,  # 1 hour timeout for large files
        )
        if result.returncode == 0:
            size_mb = local_path.stat().st_size / (1024 * 1024)
            logger.info(f"Downloaded ({size_mb:.1f} MB): {local_path.name}")
            return True
        else:
            logger.error(f"Download failed for {s3_key}")
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"Download timed out for {s3_key}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Download CSE-CIC-IDS2018 dataset from AWS Open Data"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available files on S3 without downloading",
    )
    parser.add_argument(
        "--days",
        nargs="+",
        choices=list(KNOWN_FILES.keys()) + ["all"],
        default=["all"],
        help="Which days to download (default: all). Use specific day keys for lighter testing.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args()

    if not check_aws_cli():
        sys.exit(1)

    if args.list:
        list_s3_files()
        return

    output_dir = Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine which files to download
    if "all" in args.days:
        days = list(KNOWN_FILES.keys())
    else:
        days = args.days

    logger.info(f"Downloading CSE-CIC-IDS2018 ({len(days)} days) to {output_dir}")
    for day in days:
        logger.info(f"  {day}: {DAY_DESCRIPTIONS.get(day, 'Unknown')}")

    # Download each file
    success = 0
    failed = 0
    for day in days:
        filename = KNOWN_FILES[day]
        s3_key = f"{S3_PROCESSED_PREFIX}{filename}"
        if download_file(s3_key, output_dir):
            success += 1
        else:
            failed += 1

    logger.info(f"\nDownload complete: {success} succeeded, {failed} failed")
    if failed > 0:
        logger.warning(
            "Some downloads failed. The S3 bucket may have different file names. "
            "Run with --list to see current bucket contents."
        )


if __name__ == "__main__":
    main()
