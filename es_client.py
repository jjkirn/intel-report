"""Thin Elasticsearch client for pulling Zeek intel.log data from Security
Onion - i.e. actual hits against the threat-intel feed fed by so-intel-feed
(ThreatFox / Feodo Tracker / URLhaus), already false-positive-filtered at
the source.
"""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ESClient:
    def __init__(self, host, index_pattern, api_key, verify_tls=False, timeout=30):
        self.host = host.rstrip("/")
        self.index_pattern = index_pattern
        self.headers = {
            "Authorization": f"ApiKey {api_key}",
            "Content-Type": "application/json",
        }
        self.verify_tls = verify_tls
        self.timeout = timeout

    def search(self, body):
        url = f"{self.host}/{self.index_pattern}/_search"
        resp = requests.post(
            url, json=body, headers=self.headers,
            verify=self.verify_tls, timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Elasticsearch query failed ({resp.status_code}): {resp.text[:500]}"
            )
        return resp.json()


def query_intel_hits(es, lookback_hours, max_indicators):
    """Group zeek.intel hits by the indicator that matched.

    For each distinct indicator (an IP or a domain from the threat feeds),
    report: how many times it was seen, which indicator type it is, which
    local hosts triggered it, which Zeek log context it showed up in
    (DNS lookup vs. an actual connection, etc.), what destination IP(s)
    were involved, and the first/last time it was seen in the window.
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.dataset": "zeek.intel"}},
                    {"range": {"@timestamp": {"gte": f"now-{lookback_hours}h", "lte": "now"}}},
                ]
            }
        },
        "aggs": {
            "by_indicator": {
                "terms": {"field": "intel.indicator", "size": max_indicators},
                "aggs": {
                    "indicator_type": {"terms": {"field": "intel.indicator_type", "size": 1}},
                    "seen_where": {"terms": {"field": "intel.seen_where", "size": 10}},
                    "sources": {"terms": {"field": "intel.sources", "size": 10}},
                    "affected_hosts": {"terms": {"field": "source.ip", "size": 20}},
                    "destination_ips": {"terms": {"field": "destination.ip", "size": 20}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                },
            }
        },
    }
    return es.search(body)


def parse_indicator_buckets(es_response):
    """Flatten the by_indicator aggregation into a list of simple dicts."""
    buckets = es_response.get("aggregations", {}).get("by_indicator", {}).get("buckets", [])
    out = []
    for b in buckets:
        type_buckets = b.get("indicator_type", {}).get("buckets", [])
        out.append({
            "indicator": b["key"],
            "indicator_type": type_buckets[0]["key"] if type_buckets else "unknown",
            "hit_count": b["doc_count"],
            "seen_where": [s["key"] for s in b.get("seen_where", {}).get("buckets", [])],
            "sources": [s["key"] for s in b.get("sources", {}).get("buckets", [])],
            "affected_hosts": [h["key"] for h in b.get("affected_hosts", {}).get("buckets", [])],
            "destination_ips": [d["key"] for d in b.get("destination_ips", {}).get("buckets", [])],
            "first_seen": b.get("first_seen", {}).get("value_as_string"),
            "last_seen": b.get("last_seen", {}).get("value_as_string"),
        })
    return out
