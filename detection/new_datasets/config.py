"""
Central configuration and dataset registry for the new-datasets pipeline.

Adding a fourth dataset is as simple as appending an entry to DATASET_REGISTRY
and writing a corresponding loader module.
"""

from pathlib import Path
from typing import Dict, Any

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent            # detection/
DATA_RAW     = PROJECT_ROOT / "data" / "raw"
DATA_MODELS  = PROJECT_ROOT / "data" / "models" / "new"
DATA_RESULTS = PROJECT_ROOT / "data" / "results"

RANDOM_STATE = 42
TEST_SIZE    = 0.20
VAL_SIZE     = 0.15          # fraction of *remaining* train after test split

# ── Unified Multi-Class Label Scheme ──────────────────────────────────────────
# Every dataset's raw labels are mapped into these 8 canonical classes.
UNIFIED_CLASSES = [
    "Benign",
    "DoS/DDoS",
    "Recon/Scan",
    "Brute Force",
    "Spoofing/MITM",
    "Web Attacks",
    "Malware/Botnet",
    "Other",
]

# ── Dataset Registry ──────────────────────────────────────────────────────────
# Each entry describes how to find and sample the dataset on disk.

DATASET_REGISTRY: Dict[str, Dict[str, Any]] = {
    "ciciot2023": {
        "display_name": "CICIoT2023",
        "data_dir": DATA_RAW / "ciciot2023",
        "file_pattern": "*.csv",
        "sample_frac": 0.10,        # stratified 10 % (dataset is very large)
        "loader_module": "detection.new_datasets.loaders.ciciot2023",
        "description": (
            "Canadian Institute for Cybersecurity – 105 IoT devices, "
            "33 attacks in 7 classes (DDoS, DoS, Recon, Web, Brute Force, "
            "Spoofing, Mirai).  Flow-level CSV features."
        ),
    },
    "edge_iiotset": {
        "display_name": "Edge-IIoTset",
        "data_dir": DATA_RAW / "edge_iiotset",
        "file_pattern": "*.csv",
        "sample_frac": 1.0,          # typically pre-selected ML version
        "loader_module": "detection.new_datasets.loaders.edge_iiotset",
        "description": (
            "Edge/Industrial IoT security dataset with multiple attack "
            "categories and heterogeneous data sources.  ML-ready CSV."
        ),
    },
    "nf_ton_iot_v3": {
        "display_name": "NF-ToN-IoT-v3",
        "data_dir": DATA_RAW / "nf_ton_iot_v3",
        "file_pattern": "*.csv",
        "sample_frac": 1.0,
        "loader_module": "detection.new_datasets.loaders.nf_ton_iot_v3",
        "description": (
            "University of Queensland NetFlow v3 – 53 extended NetFlow "
            "features, 9 attack types + normal, binary and multi-class labels."
        ),
    },
}


def get_dataset_config(name: str) -> Dict[str, Any]:
    """Return the config dict for a registered dataset."""
    name = name.lower().replace("-", "_")
    if name not in DATASET_REGISTRY:
        raise KeyError(
            f"Unknown dataset '{name}'.  "
            f"Registered: {list(DATASET_REGISTRY.keys())}"
        )
    return DATASET_REGISTRY[name]
