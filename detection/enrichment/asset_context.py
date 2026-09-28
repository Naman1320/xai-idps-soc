"""
Asset Context: Maps IP addresses to asset criticality ratings.

Loads asset inventory from detection/config/asset_inventory.yaml.
"""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).parent.parent / "config"


class AssetContext:
    """
    Looks up asset criticality for a given IP address.

    In a real deployment, this would query a CMDB or asset management system.
    For this project, it reads from a simple YAML inventory file.
    """

    def __init__(self, config_path: Path | None = None):
        if config_path is None:
            config_path = CONFIG_DIR / "asset_inventory.yaml"

        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        # Build IP → criticality lookup
        self.ip_criticality = {}
        for asset in self.config.get("assets", []):
            self.ip_criticality[asset["ip"]] = {
                "name": asset.get("name", "Unknown"),
                "criticality": asset.get("criticality", 0.5),
                "description": asset.get("description", ""),
            }

        self.default_criticality = self.config.get("default_criticality", 0.5)
        logger.info(f"Asset context loaded with {len(self.ip_criticality)} assets")

    def get_criticality(self, ip: str) -> float:
        """
        Get criticality score for an IP address.

        Args:
            ip: IP address string.

        Returns:
            Criticality score (0.0 to 1.0).
        """
        asset = self.ip_criticality.get(ip)
        if asset:
            return asset["criticality"]
        return self.default_criticality

    def get_asset_info(self, ip: str) -> dict:
        """Get full asset info for an IP."""
        asset = self.ip_criticality.get(ip)
        if asset:
            return asset
        return {
            "name": "Unknown",
            "criticality": self.default_criticality,
            "description": "Not in asset inventory",
        }
