# intel-report

Daily threat-intel hits report for the home LAN, built from Security
Onion's Zeek **Intel Framework** log (`intel.log`, pulled via the
Elasticsearch REST API). Produces one HTML page listing every distinct
indicator (bad IP or domain) that actually matched in the window, which
local host(s) triggered it, how it was seen (a connection, a DNS lookup,
a TLS server name, etc.), which feed flagged it, and enriched info
(org/location, via ipinfo.io) on the relevant IP(s).

This is the companion report to
[`so-intel-feed`](https://github.com/jjkirn/so-intel-feed), which runs on
`so1` and keeps Zeek's Intel Framework fed with ThreatFox / Feodo Tracker /
URLhaus indicators (already filtered to drop known false-positive-prone
shared-hosting domains like github.com). This report just reads the
*results* of that feed - the actual matches Zeek logged - so you don't have
to go digging through Security Onion's Hunt UI by hand.

Meant to run once a day from cron on `velo`, same as
[`dns-report`](https://github.com/jjkirn/dns-report) (a different report,
different purpose, kept as a separate project on purpose).

## How it works

Queries Security Onion's Elasticsearch for `event.dataset:"zeek.intel"`
documents and aggregates them by indicator, so repeated hits on the same
bad IP/domain show up as one row with a hit count, not a wall of duplicate
entries.

## Setup

1. **Install dependencies** (Python 3.8+):

   ```bash
   pip3 install --break-system-packages -r requirements.txt
   ```

2. **Copy the config file and adjust it** if needed (so1's host/IP, output
   directory, etc. - the defaults already match your setup):

   ```bash
   cp config.example.yaml config.yaml
   ```

3. **Set the Elasticsearch API key as an environment variable** - this is
   deliberately kept OUT of config.yaml and the git repo. If you already
   have the `dns-report-readonly` API key from the `dns-report` project,
   the same key works fine here too (it's reading the same Elasticsearch
   instance). Otherwise create one the same way in Kibana.

   ```bash
   echo "export INTEL_REPORT_ES_API_KEY='<paste the API key here>'" > .env
   chmod 600 .env
   source .env
   ```

   For cron, source it inside the cron job itself (see below) rather than
   relying on an interactive shell having it set.

   Optional: if you later get an ipinfo.io token, set
   `INTEL_REPORT_IPINFO_TOKEN` the same way.

4. **Test it by hand first:**

   ```bash
   source .env
   python3 intel_report.py
   ```

   This should print something like:
   ```
   Wrote /var/www/html/intel_report/intel_report_2026-11-08.html
   Wrote /var/www/html/intel_report/index.html
   Intel hits: 0 distinct indicator(s)
   ```
   (Zero is the good outcome - it means nothing on your network has matched
   a known-bad IP/domain recently.)

   If `config.yaml`'s `output_dir` isn't writable by your user, either
   `chmod`/`chown` it, or point `output_dir` somewhere in your home
   directory and have your web server's docroot symlink to it - whichever's
   easier on velo. If you already set this up for `dns-report`, a sibling
   directory under the same web root works well, e.g.
   `/var/www/html/intel_report` next to `/var/www/html/dns_report`.

5. **Check the output** by opening `index.html` in a browser.

6. **Schedule it daily with cron:**

   ```bash
   crontab -e
   ```

   Add a line like (runs at 6:05 AM, just after the dns-report job - adjust
   to taste):

   ```
   5 6 * * * cd /home/jim/intel-report && source .env && /usr/bin/python3 intel_report.py >> run.log 2>&1
   ```

## Files

| File | Purpose |
|---|---|
| `intel_report.py` | Main entry point - run this |
| `config.example.yaml` / `config.yaml` | Settings (so1 host, output path, etc.) |
| `config.py` | Loads config.yaml + required env vars |
| `es_client.py` | Builds/runs the Elasticsearch query against `zeek.intel` |
| `ip_enrich.py` | ipinfo.io lookups with an on-disk cache (`ip_cache.json`) |
| `templates/report.html.j2` | The HTML report layout |
| `tests/` | Unit tests against synthetic fixtures (no live network needed) |

## Running the tests

```bash
pip3 install --break-system-packages pytest
python3 -m pytest tests/ -v
```

These run entirely against fixture data in `tests/fixtures/` - they don't
touch your real Elasticsearch or ipinfo.io, so they're safe to run
anywhere, including before you've even set up `config.yaml`.

## Checking further back (e.g. while traveling)

By default the report only looks at the last 24 hours. If you want to look
back further on demand - say you've been out of town for a week and want to
catch up - use `--hours` to override the window for just that one run:

```bash
source .env
python3 intel_report.py --hours 168 --debug   # 168h = 7 days
```

This writes its own `intel_report_lookback_168h.html` file rather than
touching `index.html`, so it won't disturb what your daily cron job has
already published as the "latest" report. The `--debug` flag also prints a
quick summary straight to your terminal, so you don't even need to open the
HTML file for a fast gut check.

## Notes / things to double check once it's live

- **Field mapping assumption**: `intel.indicator`, `intel.indicator_type`,
  and `intel.seen_where` are used as-is, matching what Security Onion's
  Hunt UI showed for `event.dataset:"zeek.intel"`. If the first real run
  errors out on one of those fields, the mapping may differ slightly -
  ping me and I'll adjust `es_client.py`.
- **`intel.sources` field**: this holds the feed attribution string (e.g.
  "ThreatFox (Remcos)") that `so-intel-feed` writes into the `meta.desc`
  column of `intel.dat`. If this field isn't actually mapped in your
  Elasticsearch, the "Feed source" column will just show nothing rather
  than erroring - not a bug, just means that particular sub-aggregation
  came back empty.
- **Lookback window**: defaults to the last 24 hours at the moment the
  script runs, same convention as `dns-report`.
- **"Zero hits" is the expected/good state.** Don't read an empty report as
  the tool being broken - it's confirmation nothing on your network has
  touched a known-bad indicator.
