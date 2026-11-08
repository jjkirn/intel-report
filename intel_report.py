#!/usr/bin/env python3
"""Daily threat-intel hits report for the home LAN, built from Security
Onion's Zeek Intel Framework log (intel.log, via Elasticsearch).

so-intel-feed (running on so1) keeps Zeek's Intel Framework fed with
indicators from ThreatFox, Feodo Tracker, and URLhaus, already filtered to
drop known false-positive-prone shared-hosting domains (github.com, AWS,
Cloudflare, etc.). Anything that still matches is a real hit worth seeing -
this report lists each distinct indicator that matched in the window,
which local host(s) triggered it, and enriches the relevant IP(s) via
ipinfo.io so you don't have to go digging in Security Onion's Hunt UI.

Usage:
    python3 intel_report.py [--config config.yaml] [--out-name intel_report.html]

Intended to run once a day from cron. See README.md for setup.
"""

import argparse
import datetime
import os

from jinja2 import Environment, FileSystemLoader

from config import load_config, ConfigError, die
from es_client import ESClient, query_intel_hits, parse_indicator_buckets
from ip_enrich import IPEnricher

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def enrich_hits(hits, enricher):
    for h in hits:
        enriched = []
        # An Intel::ADDR indicator IS an IP - enrich it directly.
        if h["indicator_type"] == "Intel::ADDR":
            info = enricher.lookup(h["indicator"])
            if info:
                enriched.append(info)
        # For a domain-type indicator, enrich whatever destination IP(s)
        # the local host actually connected to as a result.
        for ip in h["destination_ips"]:
            if h["indicator_type"] == "Intel::ADDR" and ip == h["indicator"]:
                continue
            info = enricher.lookup(ip)
            if info:
                enriched.append(info)
        h["enriched"] = enriched
    return hits


def build_report(cfg):
    es = ESClient(
        host=cfg["elasticsearch"]["host"],
        index_pattern=cfg["elasticsearch"]["index_pattern"],
        api_key=cfg["_es_api_key"],
        verify_tls=cfg["elasticsearch"].get("verify_tls", False),
        timeout=cfg["elasticsearch"].get("request_timeout_sec", 30),
    )

    lookback_hours = cfg["report"]["lookback_hours"]
    max_indicators = cfg["report"]["max_indicators"]

    resp = query_intel_hits(es, lookback_hours, max_indicators)
    hits = parse_indicator_buckets(resp)

    # Busiest / most-recently-seen indicators first - most useful at a glance.
    hits.sort(key=lambda h: (h["hit_count"], h["last_seen"] or ""), reverse=True)

    enricher = IPEnricher(
        cache_path=os.path.join(SCRIPT_DIR, cfg["ip_enrichment"]["cache_file"]),
        token=cfg["_ipinfo_token"],
        ttl_days=cfg["ip_enrichment"].get("cache_ttl_days", 30),
    )
    enrich_hits(hits, enricher)
    enricher.save()

    return hits


def render_html(hits, cfg):
    env = Environment(loader=FileSystemLoader(os.path.join(SCRIPT_DIR, "templates")))
    tpl = env.get_template("report.html.j2")
    now = datetime.datetime.now()
    return tpl.render(
        report_date=now.strftime("%Y-%m-%d"),
        generated_at=now.strftime("%Y-%m-%d %H:%M:%S"),
        lookback_hours=cfg["report"]["lookback_hours"],
        hits=hits,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=None, help="Path to config.yaml")
    parser.add_argument("--out-name", default=None,
                         help="Override output filename (default: intel_report_YYYY-MM-DD.html)")
    parser.add_argument("--debug", action="store_true",
                         help="Print per-indicator detail to stdout")
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        die(str(e))

    try:
        hits = build_report(cfg)
    except Exception as e:
        die(f"Failed to build report: {e}")

    html = render_html(hits, cfg)

    out_dir = cfg["report"]["output_dir"]
    os.makedirs(out_dir, exist_ok=True)

    today = datetime.date.today().isoformat()
    out_name = args.out_name or f"intel_report_{today}.html"
    out_path = os.path.join(out_dir, out_name)
    with open(out_path, "w") as f:
        f.write(html)

    # Also write/refresh an "index.html" so there's always a stable latest-report URL.
    latest_path = os.path.join(out_dir, "index.html")
    with open(latest_path, "w") as f:
        f.write(html)

    print(f"Wrote {out_path}")
    print(f"Wrote {latest_path}")
    print(f"Intel hits: {len(hits)} distinct indicator(s)")

    if args.debug:
        print("\n--- Hit detail ---")
        for h in hits:
            print(f"  {h['indicator']:40s} type={h['indicator_type']:14s} "
                  f"count={h['hit_count']:<4d} hosts={h['affected_hosts']} "
                  f"sources={h['sources']} last_seen={h['last_seen']}")


if __name__ == "__main__":
    main()
