#!/bin/sh
# Fetch the offensive.agency hosts feed for OffensiveAgency::feed_file mode.
#
# usage: fetch-feed.sh DIR [PROXY]
#   DIR    directory for hosts.ndjson (+ hosts.etag); point feed_file at
#          DIR/hosts.ndjson
#   PROXY  optional curl -x proxy, e.g. http://proxy.example.org:3128
#          (or set https_proxy in the environment)
#
# Conditional (ETag) request; the file is replaced atomically and only on a
# complete 200, so Zeek never reads a partial or empty feed. Exit status is
# non-zero on failure, so cron mails you.
#
# cron example (every 30 min, the feed changes about daily):
#   */30 * * * *  /path/to/offensive-agency/tools/fetch-feed.sh /var/lib/zeek/offensive-agency

set -u
URL=${OA_FEED_URL:-https://www.offensive.agency/api/v1/feeds/hosts.ndjson}
DIR=${1:?usage: fetch-feed.sh DIR [PROXY]}
PROXY=${2:-}

cd "$DIR" || exit 1
tmp=hosts.ndjson.$$
etag=hosts.etag.$$
trap 'rm -f "$tmp" "$etag"' EXIT

set -- -sS -L --compressed -m 120 -A zeek-offensive-agency-cron \
       -w '%{http_code}' --etag-save "$etag" -o "$tmp"
[ -n "$PROXY" ] && set -- "$@" -x "$PROXY"
[ -s hosts.etag ] && [ -s hosts.ndjson ] && set -- "$@" --etag-compare hosts.etag

code=$(curl "$@" "$URL") || { echo "fetch-feed: curl failed (http=$code)" >&2; exit 1; }

case "$code" in
304) exit 0 ;;
200)
	# Sanity: non-empty and the first line looks like a JSON host record.
	if [ -s "$tmp" ] && head -c 1 "$tmp" | grep -q '{'; then
		chmod 644 "$tmp"
		mv -f "$tmp" hosts.ndjson && mv -f "$etag" hosts.etag
		exit 0
	fi
	echo "fetch-feed: 200 but body is empty or not NDJSON; kept old copy" >&2
	exit 1 ;;
*)
	echo "fetch-feed: HTTP $code from $URL; kept old copy" >&2
	exit 1 ;;
esac
