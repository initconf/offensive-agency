##! offensive-agency: core definitions and the manager-side decision engine.
##!
##! Every detection path in this package -- Intel framework matches on the
##! feed's IPs and domains, behavioural signatures seen on workers, and the
##! feed's own health checks -- ends in a single event, OffensiveAgency::hit,
##! that runs on ONE node: the manager in a cluster, the only process when
##! standalone. That node owns all decision state (dedup window, feed
##! metadata used for enrichment), so each logical finding is logged and
##! noticed exactly once, no matter how many workers saw it.
##!
##! Why the manager and not HRW-to-proxy: the Intel framework already
##! delivers Intel::match on the manager, and the feed metadata used to
##! enrich behavioural hits also lives there. Hit volume is bounded by the
##! feed size and the signature set (not by traffic volume), and workers
##! pre-filter repeats before publishing, so the manager is never a hot spot.
##!
##! All tunables are Config framework options: set them in a config file
##! (see offensive-agency.cfg.example) rather than with redef. They can be
##! changed at runtime without restarting Zeek.

@load base/frameworks/cluster
@load base/frameworks/notice
@load base/frameworks/config
@load base/utils/site

module OffensiveAgency;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	redef enum Notice::Type += {
		## A local host opened a TCP connection to a host the feed lists
		## as running an exposed offensive AI agent console. Either
		## someone inside is operating or browsing the agent, or a
		## compromised host is calling back to it.
		Outbound_To_Agent_Host,
		## A listed agent host completed a TCP connection to a local
		## host (or appeared in X-Forwarded-For): the agent's tooling
		## actually talked to one of your services.
		Inbound_From_Agent_Host,
		## A local host resolved, or used as TLS SNI or HTTP Host, a
		## domain name the feed lists as serving an agent console.
		Agent_Domain_Contact,
		## An inbound HTTP request carried a signature of a known
		## offensive AI agent (User-Agent, header or payload marker).
		Agent_Activity_Inbound,
		## A local host sent traffic signed by an offensive AI agent
		## (its User-Agent, markers, or its update/telemetry endpoints):
		## an agent is running inside your network.
		Agent_Running_Locally,
		## Web-shell or implant traffic of an agent's built-in C2
		## (e.g. CyberStrikeAI-WebShell, X-Implant-Token). Treat as a
		## full intrusion.
		Agent_Implant_Or_Webshell,
		## A local host looked up an out-of-band (OAST) callback domain
		## (dnslog.cn, interactsh): a blind injection probably landed.
		OAST_Callback_Lookup,
		## One of YOUR addresses is listed in the feed: a local host
		## exposes an offensive AI agent console to the Internet.
		Local_Host_Listed,
		## The feed could not be fetched or parsed, or its data is stale.
		Feed_Problem,
	};

	## One finding. Built on the node that saw it, fully serialized, and
	## decided on the manager.
	type Hit: record {
		ts:          time     &log;
		uid:         string   &log &optional;
		id:          conn_id  &log &optional;
		## ip, domain, ua, header, uri, method, dns, sni, local_listed
		kind:        string   &log;
		## The indicator or signature id that matched.
		indicator:   string   &log;
		## Where it was seen (Intel where, or the protocol field).
		seen_where:  string   &log &optional;
		## inbound, outbound, internal or transit.
		direction:   string   &log &optional;
		local_host:  addr     &log &optional;
		remote_host: addr     &log &optional;
		## Agents and detection levels, e.g. "artex:confirmed".
		agents:      string   &log &optional;
		## attack, operator, implant, webshell, oast, infra
		role:        string   &log &optional;
		## Feed context: network, co-hosted C2, first/last seen.
		context:     string   &log &optional;
		## Signature description (behavioural hits only).
		sig_desc:    string   &optional;
		## Weak signatures are logged but never noticed on their own.
		weak:        bool     &default=F;
		## The notice raised for this hit, if any.
		note:        Notice::Type &log &optional;
	};

	## Routed to the authoritative node (manager / standalone process).
	global hit: event(h: Hit);

	## Raised after the authoritative node logged a hit.
	global log_offensive_agency: event(rec: Hit);

	## Raised on the authoritative node after a feed load was applied.
	global feed_updated: event(n_ips: count, n_domains: count);

	# -----------------------------------------------------------------
	# Config framework options. Set these in a config file loaded via
	# Config::config_files; see offensive-agency.cfg.example.
	# -----------------------------------------------------------------

	## Feed to pull (NDJSON, one host per line, active 7-day window).
	option feed_url = "https://www.offensive.agency/api/v1/feeds/hosts.ndjson";

	## If non-empty, read the feed from this local NDJSON file instead of
	## fetching over HTTP. For air-gapped sensors fed by a cron job, and
	## for tests. The file is re-read every refresh_interval.
	option feed_file = "";

	## How often to poll. Requests are conditional (ETag), so a poll that
	## finds nothing new costs one small 304 response. The upstream data
	## changes about once a day.
	option refresh_interval = 30 min;

	## Maximum time for one download.
	option fetch_timeout = 2 min;

	## Directory (relative to the node's working directory, or absolute)
	## for the cached feed and its ETag. The cache lets a restarted manager
	## load indicators immediately, even while the API is unreachable.
	option state_dir = "offensive-agency-state";

	## curl binary used for fetching.
	option curl_path = "curl";

	## HTTP(S) proxy for the fetch, passed to curl as ``-x``, e.g.
	## "http://proxy.example.org:3128" or "socks5h://127.0.0.1:1080".
	## Empty (default): connect directly; curl still honours the
	## https_proxy / no_proxy environment variables in that case.
	option fetch_proxy = "";

	## Lowest detection level to act on: "confirmed" (two independent
	## fingerprint families) or "probable" (one).
	option min_level = "confirmed";

	## Insert IPs the feed marks as shared CDN fronts. Off by default: a
	## CDN address fronts thousands of unrelated sites. Their domain
	## names are still watched.
	option include_cdn_ips = F;

	## Only watch IPs last seen within this long before the feed's newest
	## observation (the feed's active window is 7 days).
	option max_ip_age = 7 days;

	## Shorter age limit for addresses in cloud provider space, which
	## are reassigned to unrelated customers quickly.
	option max_cloud_ip_age = 3 days;

	## Detection paths that can be switched off independently.
	option watch_ips = T;
	option watch_domains = T;
	option watch_behaviour = T;
	option watch_oast = T;

	## Local hosts or networks to ignore entirely (your own pentest
	## boxes, vulnerability scanners, researchers who study these tools).
	option ignore_hosts: set[subnet] = {};

	## Feed indicators (IP or domain) never to watch.
	option ignore_indicators: set[string] = {};

	## Inbound connections from listed hosts to these local ports are
	## logged but not noticed (e.g. 25/tcp if agent boxes that also run
	## mail servers deliver mail to you).
	option inbound_ignore_ports: set[port] = {};

	## Behavioural signature ids to disable (see traces.zeek).
	option disabled_signatures: set[string] = {};

	## A repeated finding (same key) is logged and noticed once per window.
	option dedup_interval = 1 day;

	## Raise Feed_Problem when no successful update for this long, or
	## when the feed's newest observation is older than this.
	option stale_after = 2 days;

	## Consecutive fetch failures before raising Feed_Problem.
	option failures_before_notice = 3;

	## Intel framework source tag for the indicators this package inserts.
	const intel_source = "offensive.agency";

	## Version string sent in the User-Agent of feed requests.
	const version = "1.0.1";

	# -----------------------------------------------------------------
	# Feed context, kept on the authoritative node (filled by feed.zeek).
	# -----------------------------------------------------------------
	type HostCtx: record {
		agents:  string;            # "artex:confirmed,hexstrike:probable"
		ports:   set[port];         # agent console ports
		kind:    string &default="";
		context: string;            # human readable network/C2/seen summary
		domains: string &default="";
	};

	global feed_hosts: table[addr] of HostCtx;
	global feed_domains: table[string] of HostCtx;

	## T on the node that owns feed and decision state.
	global is_authority: function(): bool;

	## Submit a hit from any node.
	global report: function(h: Hit);
}

function is_authority(): bool
	{
	return ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER;
	}

## Worker-side pre-filter: don't re-publish a key this node already sent
## recently. Optimization only; the authoritative node dedups for real.
global sent_cache: set[string] &create_expire=10 min;

function report(h: Hit)
	{
	local key = fmt("%s|%s|%s|%s", h$kind, h$indicator,
	                h?$id ? cat(h$id$orig_h) : "", h?$id ? cat(h$id$resp_h) : "");
	if ( key in sent_cache )
		return;
	add sent_cache[key];

	if ( is_authority() )
		event OffensiveAgency::hit(h);
	else
		Cluster::publish(Cluster::manager_topic, OffensiveAgency::hit, h);
	}

## Authoritative dedup state. Keys are logical identities (see dedup_key).
global seen_keys: set[string] &create_expire=1 day;

function ignored(a: addr): bool
	{
	for ( sn in ignore_hosts )
		if ( a in sn )
			return T;
	return F;
	}

## Classify direction from the connection endpoints.
function direction_of(id: conn_id): string
	{
	local ol = Site::is_local_addr(id$orig_h);
	local rl = Site::is_local_addr(id$resp_h);
	if ( ol && rl ) return "internal";
	if ( ol ) return "outbound";
	if ( rl ) return "inbound";
	return "transit";
	}

## Decide the notice type (if any) for a hit. Returns F to log only.
function decide(h: Hit): bool
	{
	switch ( h$kind ) {
	case "local_listed":
		h$note = Local_Host_Listed;
		return T;

	case "feed":
		h$note = Feed_Problem;
		return T;

	case "ip":
		if ( h$direction == "inbound" )
			{
			if ( h?$id && h$id$resp_p in inbound_ignore_ports )
				return F;
			h$note = Inbound_From_Agent_Host;
			return T;
			}
		if ( h$direction == "outbound" )
			{
			h$note = Outbound_To_Agent_Host;
			return T;
			}
		return F;

	case "domain":
		h$note = Agent_Domain_Contact;
		return T;
	}

	# Behavioural signatures.
	if ( h$role == "implant" || h$role == "webshell" )
		{
		h$note = Agent_Implant_Or_Webshell;
		return T;
		}

	if ( h$weak )
		return F;

	if ( h$role == "oast" )
		{
		if ( h$direction == "outbound" || h$direction == "internal" )
			{
			h$note = OAST_Callback_Lookup;
			return T;
			}
		return F;
		}

	if ( h$direction == "outbound" || h$direction == "internal" )
		{
		h$note = Agent_Running_Locally;
		return T;
		}

	if ( h$direction == "inbound" && h$role == "attack" )
		{
		h$note = Agent_Activity_Inbound;
		return T;
		}

	return F;
	}

## The logical identity of a finding: what a human would call "the same
## alert". Deliberately coarse for inbound activity (one per remote host)
## and per local host for things that need a per-host response.
function dedup_key(h: Hit): string
	{
	local lh = h?$local_host ? cat(h$local_host) : "";
	local rh = h?$remote_host ? cat(h$remote_host) : "";

	switch ( h$kind ) {
	case "ip":
		if ( h$direction == "inbound" )
			return fmt("ip-in|%s", rh);
		return fmt("ip-out|%s|%s", rh, lh);
	case "domain":
		return fmt("domain|%s|%s", h$indicator, lh);
	case "local_listed":
		return fmt("local|%s", h$indicator);
	case "feed":
		return fmt("feed|%s", h$indicator);
	}

	if ( h$role == "implant" || h$role == "webshell" )
		return fmt("implant|%s|%s|%s", h$agents, lh, rh);
	if ( h$role == "oast" )
		return fmt("oast|%s|%s", h$indicator, lh);
	if ( h$direction == "inbound" )
		return fmt("beh-in|%s|%s", h$agents, rh);
	return fmt("beh-local|%s|%s", h$agents, lh);
	}

function notice_msg(h: Hit): string
	{
	local rp = h?$id ? cat(h$id$resp_p) : "";

	switch ( h$note ) {
	case Outbound_To_Agent_Host:
		local console = "";
		if ( h?$remote_host && h$remote_host in feed_hosts && h?$id &&
		     h$id$resp_p in feed_hosts[h$remote_host]$ports )
			console = " on its agent console port";
		return fmt("%s connected to %s:%s%s, a host running an exposed offensive AI agent (%s)",
		           h$local_host, h$remote_host, rp, console, h$agents);
	case Inbound_From_Agent_Host:
		return fmt("Offensive AI agent host %s (%s) connected to %s:%s%s",
		           h$remote_host, h$agents, h$local_host, rp,
		           h$seen_where == "HTTP::IN_X_FORWARDED_FOR_HEADER" ? " (via X-Forwarded-For)" : "");
	case Agent_Domain_Contact:
		return fmt("%s used offensive AI agent domain %s (%s) in %s",
		           h$local_host, h$indicator, h$agents, h$seen_where);
	case Agent_Activity_Inbound:
		return fmt("Offensive AI agent traffic (%s) from %s to %s:%s: %s",
		           h$agents, h$remote_host, h$local_host, rp, h$sig_desc);
	case Agent_Running_Locally:
		return fmt("Local host %s emits traffic of offensive AI agent %s: %s",
		           h$local_host, h$agents, h$sig_desc);
	case Agent_Implant_Or_Webshell:
		return fmt("Offensive AI agent implant/web-shell traffic (%s) between %s and %s: %s",
		           h$agents, h$id$orig_h, h$id$resp_h, h$sig_desc);
	case OAST_Callback_Lookup:
		return fmt("%s looked up out-of-band callback domain %s (%s): a blind injection may have succeeded",
		           h$local_host, h$seen_where, h$agents);
	case Local_Host_Listed:
		return fmt("Local host %s is listed as exposing an offensive AI agent console (%s)",
		           h$indicator, h$agents);
	case Feed_Problem:
		return fmt("offensive.agency feed problem: %s", h$context);
	}
	return "offensive.agency finding";
	}

event OffensiveAgency::hit(h: Hit) &priority=5
	{
	# Only the authoritative node decides. A worker never sees this event
	# unless something publishes to it by mistake; ignore it there.
	if ( ! is_authority() )
		return;

	if ( h?$local_host && ignored(h$local_host) )
		return;

	# Enrich with feed context when the remote end is a listed host.
	if ( h?$remote_host && h$remote_host in feed_hosts )
		{
		local fh = feed_hosts[h$remote_host];
		if ( ! h?$agents )
			h$agents = fh$agents;
		if ( ! h?$context )
			h$context = fh$context;
		else if ( h$context != fh$context )
			h$context = fmt("%s; remote is a listed agent host: %s", h$context, fh$context);
		}

	local key = dedup_key(h);
	if ( key in seen_keys )
		return;
	add seen_keys[key];

	local do_notice = decide(h);

	Log::write(OffensiveAgency::LOG, h);

	if ( ! do_notice )
		return;

	local n = Notice::Info($note=h$note, $msg=notice_msg(h),
	                       $identifier=key, $suppress_for=dedup_interval);
	if ( h?$context )
		n$sub = h$context;
	if ( h?$uid )
		n$uid = h$uid;
	if ( h?$id )
		n$id = h$id;

	# $src is the address a responder acts on: the remote end for inbound
	# findings (agent host, scanner, web-shell operator), the local host
	# otherwise.
	if ( h?$direction && h$direction == "inbound" && h?$remote_host && h?$local_host )
		{
		n$src = h$remote_host;
		n$dst = h$local_host;
		}
	else if ( h?$local_host )
		{
		n$src = h$local_host;
		if ( h?$remote_host )
			n$dst = h$remote_host;
		}
	if ( h?$id )
		n$p = h$id$resp_p;

	NOTICE(n);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(OffensiveAgency::LOG, [$columns=Hit, $ev=log_offensive_agency,
	                   $path="offensive_agency", $policy=log_policy]);
	}
