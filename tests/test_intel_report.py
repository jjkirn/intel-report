"""Tests run entirely against synthetic fixtures - no live Elasticsearch
needed. Run with: python3 -m pytest tests/ -v
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from es_client import parse_indicator_buckets
from intel_report import enrich_hits

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def read_json_fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


def test_parse_indicator_buckets_flattens_aggregation():
    hits = parse_indicator_buckets(read_json_fixture("intel_hits_response.json"))
    assert len(hits) == 2

    addr_hit = next(h for h in hits if h["indicator"] == "185.220.101.45")
    assert addr_hit["indicator_type"] == "Intel::ADDR"
    assert addr_hit["hit_count"] == 7
    assert addr_hit["affected_hosts"] == ["192.168.1.120"]
    assert addr_hit["sources"] == ["ThreatFox (Remcos)"]
    assert addr_hit["seen_where"] == ["Conn::IN_ORIG"]
    assert addr_hit["first_seen"] == "2026-11-08T02:10:00.000Z"
    assert addr_hit["last_seen"] == "2026-11-08T09:45:00.000Z"

    domain_hit = next(h for h in hits if h["indicator"] == "evil-c2-domain.example")
    assert domain_hit["indicator_type"] == "Intel::DOMAIN"
    assert domain_hit["destination_ips"] == ["203.0.113.9"]


def test_parse_indicator_buckets_handles_empty_response():
    hits = parse_indicator_buckets(read_json_fixture("intel_hits_empty.json"))
    assert hits == []


def test_parse_indicator_buckets_defaults_missing_subaggs_gracefully():
    """If a sub-aggregation field isn't mapped in this ES version (e.g. no
    intel.sources field exists), the bucket just comes back with no 'sources'
    key entirely - make sure we don't blow up on that."""
    response = {
        "aggregations": {
            "by_indicator": {
                "buckets": [
                    {
                        "key": "9.9.9.9",
                        "doc_count": 1,
                        "indicator_type": {"buckets": [{"key": "Intel::ADDR", "doc_count": 1}]},
                        "first_seen": {"value_as_string": "2026-11-08T00:00:00.000Z"},
                        "last_seen": {"value_as_string": "2026-11-08T00:00:00.000Z"},
                    }
                ]
            }
        }
    }
    hits = parse_indicator_buckets(response)
    assert len(hits) == 1
    assert hits[0]["sources"] == []
    assert hits[0]["seen_where"] == []
    assert hits[0]["affected_hosts"] == []
    assert hits[0]["destination_ips"] == []


class FakeEnricher:
    """Records which IPs were looked up and returns a fixed fake result."""

    def __init__(self):
        self.looked_up = []

    def lookup(self, ip):
        self.looked_up.append(ip)
        if ip == "0.0.0.0":
            return None
        return {"ip": ip, "org": "Fake Org", "city": "", "region": "", "country": "", "error": None}


def test_enrich_hits_enriches_addr_indicator_directly():
    hits = [{
        "indicator": "185.220.101.45",
        "indicator_type": "Intel::ADDR",
        "destination_ips": ["185.220.101.45"],
    }]
    enricher = FakeEnricher()
    enrich_hits(hits, enricher)
    # Should look up the indicator once, and not double-enrich the same IP
    # again just because it also appears in destination_ips.
    assert enricher.looked_up == ["185.220.101.45"]
    assert len(hits[0]["enriched"]) == 1


def test_enrich_hits_enriches_destination_ips_for_domain_indicator():
    hits = [{
        "indicator": "evil-c2-domain.example",
        "indicator_type": "Intel::DOMAIN",
        "destination_ips": ["203.0.113.9", "203.0.113.10"],
    }]
    enricher = FakeEnricher()
    enrich_hits(hits, enricher)
    assert set(enricher.looked_up) == {"203.0.113.9", "203.0.113.10"}
    assert len(hits[0]["enriched"]) == 2


def test_hours_flag_is_wired_into_the_cli():
    """--hours should exist as a real CLI flag (so a one-off --hours 168
    lookback while traveling doesn't require editing config.yaml)."""
    result = subprocess.run(
        [sys.executable, os.path.join(SCRIPT_DIR, "intel_report.py"), "--help"],
        capture_output=True, text=True,
    )
    assert "--hours" in result.stdout
    assert "--out-name" in result.stdout


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
