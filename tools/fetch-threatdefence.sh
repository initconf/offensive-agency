#!/bin/sh
# Fetch ThreatDefence's sourced indicators (MIT licensed,
# https://github.com/ThreatDefence/agentic-attack-detections) and convert
# the network ones into the file OffensiveAgency::td_file reads.
#
# usage: fetch-threatdefence.sh DIR [PROXY]
#   DIR    directory for threatdefence.tsv (+ cache files); point td_file
#          at DIR/threatdefence.tsv
#   PROXY  optional curl -x proxy (or set https_proxy in the environment)
#
# Keeps only IPv4 addresses and domains, with their confidence, actor,
# context, report URL and review-by date; Zeek applies the confidence,
# expiry and ignore filters (so they can be changed without a refetch).
# The output is replaced atomically and only after a sane download and
# conversion. Exit status is non-zero on failure, so cron mails you.
#
# cron example (upstream changes a few times a week):
#   23 */6 * * *  /path/to/offensive-agency/tools/fetch-threatdefence.sh /var/lib/zeek/offensive-agency

set -u
URL=${TD_CSV_URL:-https://raw.githubusercontent.com/ThreatDefence/agentic-attack-detections/main/iocs/indicators.csv}
DIR=${1:?usage: fetch-threatdefence.sh DIR [PROXY]}
PROXY=${2:-}

cd "$DIR" || exit 1
csv=td-indicators.csv.$$
etag=td-indicators.etag.$$
tsv=threatdefence.tsv.$$
trap 'rm -f "$csv" "$etag" "$tsv"' EXIT

set -- -sS -L --compressed -m 120 -A zeek-offensive-agency-cron \
       -w '%{http_code}' --etag-save "$etag" -o "$csv"
[ -n "$PROXY" ] && set -- "$@" -x "$PROXY"
[ -s td-indicators.etag ] && [ -s threatdefence.tsv ] && set -- "$@" --etag-compare td-indicators.etag

code=$(curl "$@" "$URL") || { echo "fetch-threatdefence: curl failed (http=$code)" >&2; exit 1; }

case "$code" in
304) exit 0 ;;
200) ;;
*)
	echo "fetch-threatdefence: HTTP $code from $URL; kept old copy" >&2
	exit 1 ;;
esac

# CSV (quoted fields with commas) -> Zeek input-framework TSV. Untrusted
# input: python -I, no tabs/newlines/control chars survive into a field.
python3 -I - "$csv" "$tsv" <<'EOF' || { echo "fetch-threatdefence: conversion failed; kept old copy" >&2; exit 1; }
import csv, re, sys

src, dst = sys.argv[1], sys.argv[2]
cols = ["value", "type", "confidence", "actor", "context", "source_url", "review_by", "framework"]
clean = re.compile(r"[\x00-\x1f\x7f]+")

with open(src, newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))
missing = [c for c in cols if rows and c not in rows[0]]
if not rows or missing:
    sys.exit(f"unexpected CSV header (missing {missing})")

out = []
for r in rows:
    if r["type"] not in ("ipv4", "domain"):
        continue
    vals = [clean.sub(" ", (r[c] or "")).strip() or "-" for c in cols]
    out.append("\t".join(vals))

if len(out) < 10:
    sys.exit(f"only {len(out)} network indicators")

with open(dst, "w", encoding="utf-8") as f:
    # "type" is a Zeek keyword: the column is ioc_type in the TSV.
    hdr = ["ioc_type" if c == "type" else c for c in cols]
    f.write("#separator \\x09\n#fields\t" + "\t".join(hdr) + "\n")
    f.write("\n".join(out) + "\n")
EOF

chmod 644 "$tsv"
mv -f "$tsv" threatdefence.tsv && mv -f "$etag" td-indicators.etag
exit 0
