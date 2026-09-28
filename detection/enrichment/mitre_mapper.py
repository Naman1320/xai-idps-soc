"""
MITRE ATT&CK Mapper: Maps detected attack classes to ATT&CK techniques.

Loads mapping from detection/config/mitre_mapping.yaml.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional

import yaml

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).parent.parent / "config"


class MitreMapper:
    """
    Static mapper from dataset attack class labels to MITRE ATT&CK techniques.

    This is a curated, manual mapping — not dynamic inference. Each attack
    class in CICIDS2017 and UNSW-NB15 is mapped to the most appropriate
    ATT&CK technique based on the attack description.
    """

    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            config_path = CONFIG_DIR / "mitre_mapping.yaml"

        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        # Build flat lookup: attack_class -> technique_info
        self.mapping: Dict[str, Dict[str, Any]] = {}

        for dataset_key in ["cicids2017", "unsw_nb15", "cse_cic_ids2018"]:
            if dataset_key in self.config:
                for attack_class, info in self.config[dataset_key].items():
                    self.mapping[attack_class] = info

        self.default = self.config.get("default", {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "severity": "Medium",
            "severity_score": 0.5,
            "description": "Unknown or unmapped attack type",
        })

        logger.info(f"MITRE mapper loaded with {len(self.mapping)} attack class mappings")

    def map(self, attack_class: str) -> Dict[str, Any]:
        """
        Map an attack class label to its MITRE ATT&CK technique.

        Args:
            attack_class: The predicted attack class label (e.g., "DDoS", "PortScan").

        Returns:
            Dict with technique_id, technique_name, tactic, severity, severity_score, description.
        """
        if attack_class.lower() in ("benign", "normal"):
            return {
                "technique_id": None,
                "technique_name": None,
                "tactic": None,
                "severity": None,
                "severity_score": 0.0,
                "description": "Benign traffic — no attack detected",
            }

        info = self.mapping.get(attack_class)
        if info is None:
            logger.warning(f"No MITRE mapping for attack class '{attack_class}', using default")
            return self.default.copy()

        return {
            "technique_id": info.get("technique_id"),
            "technique_name": info.get("technique_name"),
            "tactic": info.get("tactic"),
            "severity": info.get("severity"),
            "severity_score": info.get("severity_score", 0.5),
            "description": info.get("description", ""),
        }
