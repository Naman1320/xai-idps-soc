"""
Tests for MITRE ATT&CK Mapper.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../detection")))

from enrichment.mitre_mapper import MitreMapper


def test_mitre_mapping_benign():
    """Verify benign flows return null technique info."""
    mapper = MitreMapper()
    res = mapper.map("Benign")
    assert res["technique_id"] is None
    assert res["severity_score"] == 0.0


def test_mitre_mapping_ddos():
    """Verify DDoS maps to T1498."""
    mapper = MitreMapper()
    res = mapper.map("DDoS")
    assert res["technique_id"] == "T1498"
    assert "Denial of Service" in res["technique_name"]


def test_mitre_mapping_portscan():
    """Verify PortScan maps to T1046."""
    mapper = MitreMapper()
    res = mapper.map("PortScan")
    assert res["technique_id"] == "T1046"


def test_mitre_mapping_unknown():
    """Verify unknown class returns fallback default technique."""
    mapper = MitreMapper()
    res = mapper.map("NonExistentAttackClass")
    assert res["technique_id"] is not None
