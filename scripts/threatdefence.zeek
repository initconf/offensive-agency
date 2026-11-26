##! Second indicator source: ThreatDefence's sourced IoCs.
##!
##! https://github.com/ThreatDefence/agentic-attack-detections (MIT) keeps a
##! hand-curated list of indicators tied to published reports of attacks by
##! offensive AI agents (Datadog, Microsoft, Wiz, CrowdStrike, Team Cymru,
##! ...): operator C2, payload and skimmer hosts, attack sources. That is
##! infrastructure the offensive.agency feed cannot see, because it only
##! finds exposed agent consoles.
##!
##! Off by default. tools/fetch-threatdefence.sh (cron) downloads their
##! iocs/indicators.csv and writes the IPv4 and domain rows to a TSV; set
##! td_file to it. The authoritative node re-reads that file every
##! refresh_interval and keeps the Intel framework in sync (source
##! "threatdefence"), the same way feed.zeek does for the main feed. Hits use
##! the same notice types and dedup keys as offensive.agency hits, so an
##! address in both sources is reported once.
##!
##! Precision filters, applied here so they can change without a refetch:
##!   - confidence >= td_min_confidence (default medium; their low rows are
##!     largely legitimate services such as AI model APIs)
##!   - IP rows past their review_by date are dropped (upstream's expiry)
##!   - single addresses only, never ranges
##!   - td_ignore_indicators (generic services) and ignore_indicators
##!   - rows whose context names shared infrastructure (td_skip_context)
##!   - domains already covered by a behavioural signature in traces.zeek
##!   - local addresses are never inserted (reported as Local_Host_Listed)

@load base/frameworks/intel
@load ./main
@load ./feed
@load ./traces

module OffensiveAgency;

export {
	## TSV written by tools/fetch-threatdefence.sh. Empty: source off.
	option td_file = "";

	## Lowest ThreatDefence confidence to watch: "high", "medium" or "low".
	option td_min_confidence = "medium";

	## Indicators from this source never to watch: legitimate, shared
	## services that upstream lists for context (callback, geolocation and
	## AI model APIs, LLM relays). Applied on top of ignore_indicators.
	option td_ignore_indicators: set[string] = {
		"webhook.site", "dnslog.cn", "api.db-ip.com", "api.deepseek.com",
		"open.bigmodel.cn", "api.x.ai", "api.anthropic.com", "api.openai.com",
		"api.keenable.ai", "us.cloud.langfuse.com", "cloud.langfuse.com",
		"bedrock-runtime.us-east-1.amazonaws.com", "api.whatai.cc", "xcai.pro",
		"code.newcli.com", "support.pentagi.com", "decepticon.red",
		"api.github.com", "raw.githubusercontent.com", "codeload.github.com",
	};

	## Skip rows whose context contains one of these (case-insensitive):
	## addresses upstream itself describes as shared (VPN exits, proxies).
	option td_skip_context: set[string] = { "vpn exit", "proxy address" };

	## Intel framework source tag of this source's indicators.
	const td_intel_source = "threatdefence";

	## Context of the watched ThreatDefence indicators (authoritative node).
	global td_hosts: table[addr] of string;
	global td_domains: table[string] of string;

	## Raised on the authoritative node after a ThreatDefence load.
	global td_updated: event(n_ips: count, n_domains: count);
}

type TDRow: record {
	value:      string &optional;
	ioc_type:   string &optional;
	confidence: string &optional;
	actor:      string &optional;
	context:    string &optional;
	source_url: string &optional;
	review_by:  string &optional;
	framework:  string &optional;
};

global td_timer: event();
global td_reapply: event();
global td_reload: event();
global td_row: event(desc: Input::EventDescription, tpe: Input::Event, r: TDRow);

global td_rows: vector of TDRow;
global td_pending: vector of TDRow;
global td_inserted: table[string] of string;
global td_load_seq = 0;
global td_current = "";
global td_busy = F;
global td_reapply_scheduled = F;
global td_running = F;

function td_rank(c: string): count
	{
	switch ( c ) {
	case "high": return 3;
	case "medium": return 2;
	case "low": return 1;
	}
	return 0;
	}

function td_skip(ctx: string): bool
	{
	local l = to_lower(ctx);
	for ( s in td_skip_context )
		if ( strstr(l, to_lower(s)) > 0 )
			return T;
	return F;
	}

function td_agents(r: TDRow): string
	{
	local conf = r?$confidence ? r$confidence : "?";
	if ( ! r?$framework )
		return fmt("unattributed:td-%s", conf);
	local v: vector of string;
	for ( _, fw in split_string(r$framework, / +/) )
		if ( fw != "" )
			v += fmt("%s:td-%s", fw, conf);
	return join_string_vec(v, ",");
	}

function td_context(r: TDRow): string
	{
	return fmt("ThreatDefence %s: %s (actor: %s) %s",
	           r?$confidence ? r$confidence : "?", r?$context ? r$context : "-",
	           r?$actor ? r$actor : "-", r?$source_url ? r$source_url : "-");
	}

function td_apply(rows: vector of TDRow)
	{
	local today = strftime("%Y-%m-%d", current_time());
	local min = td_rank(td_min_confidence);
	local new_hosts: table[addr] of string;
	local new_domains: table[string] of string;
	local agents_of: table[string] of string;
	local desired: set[string];

	for ( i in rows )
		{
		local r = rows[i];
		if ( ! r?$value || ! r?$ioc_type || ! r?$confidence )
			next;
		if ( td_rank(r$confidence) < min || td_rank(r$confidence) == 0 )
			next;
		local v = to_lower(r$value);
		if ( v in td_ignore_indicators || v in ignore_indicators )
			next;
		if ( r?$context && td_skip(r$context) )
			next;

		if ( r$ioc_type == "ipv4" )
			{
			if ( ! watch_ips || ! is_valid_ip(v) )
				next;	# ranges ("/") are deliberately not watched
			if ( r?$review_by && r$review_by < today )
				next;
			local ip = to_addr(v);
			if ( Site::is_local_addr(ip) )
				{
				report(Hit($ts=network_time(), $kind="local_listed", $indicator=v,
				           $local_host=ip, $agents=td_agents(r), $context=td_context(r),
				           $role="infra", $source=td_intel_source));
				next;
				}
			new_hosts[ip] = td_context(r);
			agents_of[fmt("ip|%s", v)] = td_agents(r);
			}
		else if ( r$ioc_type == "domain" )
			{
			if ( ! watch_domains )
				next;
			# Already a behavioural signature (e.g. update.pentagi.com):
			# one detection per lookup is enough.
			if ( match_sig("dns", v, "") != "" )
				next;
			new_domains[v] = td_context(r);
			agents_of[fmt("dom|%s", v)] = td_agents(r);
			}
		}

	for ( a in new_hosts )
		add desired[fmt("ip|%s", a)];
	for ( dn in new_domains )
		add desired[fmt("dom|%s", dn)];

	for ( key in desired )
		{
		local kv = split_string1(key, /\|/);
		local is_ip = kv[0] == "ip";
		local ctx2 = is_ip ? new_hosts[to_addr(kv[1])] : new_domains[kv[1]];
		local fp = fmt("%s|%s", agents_of[key], ctx2);
		if ( key in td_inserted && td_inserted[key] == fp )
			next;
		td_inserted[key] = fp;
		Intel::insert([$indicator=kv[1], $indicator_type=is_ip ? Intel::ADDR : Intel::DOMAIN,
		               $meta=[$source=td_intel_source, $desc=ctx2, $oa_agents=agents_of[key],
		                      $url="https://github.com/ThreatDefence/agentic-attack-detections"]]);
		}

	# Same removal guard as the main feed.
	if ( |td_inserted| > 20 && |desired| * 2 < |td_inserted| )
		feed_problem("td-shrunk", fmt("ThreatDefence indicators shrank from %d to %d; not removing any",
		                              |td_inserted|, |desired|));
	else
		{
		local gone: vector of string;
		for ( ikey in td_inserted )
			if ( ikey !in desired )
				gone += ikey;
		for ( gi in gone )
			{
			local gkv = split_string1(gone[gi], /\|/);
			Intel::remove([$indicator=gkv[1], $indicator_type=gkv[0] == "ip" ? Intel::ADDR : Intel::DOMAIN,
			               $meta=[$source=td_intel_source]], F);
			delete td_inserted[gone[gi]];
			}
		}

	td_hosts = new_hosts;
	td_domains = new_domains;
	event OffensiveAgency::td_updated(|new_hosts|, |new_domains|);
	}

event OffensiveAgency::td_row(desc: Input::EventDescription, tpe: Input::Event, r: TDRow)
	{
	if ( desc$name == td_current )
		td_pending += r;
	}

function td_load()
	{
	if ( td_file == "" || td_busy )
		return;
	if ( file_size(td_file) < 0 )
		{
		feed_problem("td-missing-file", fmt("ThreatDefence file %s does not exist (tools/fetch-threatdefence.sh not running?)",
		                                    td_file));
		return;
		}
	td_busy = T;
	++td_load_seq;
	td_current = fmt("offensive-agency-td-%d", td_load_seq);
	td_pending = vector();
	Input::add_event([$source=td_file, $name=td_current, $reader=Input::READER_ASCII,
	                  $mode=Input::MANUAL, $fields=TDRow, $want_record=T,
	                  $ev=OffensiveAgency::td_row]);
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name != td_current )
		return;
	Input::remove(name);
	td_current = "";
	td_busy = F;
	if ( |td_pending| == 0 )
		{
		feed_problem("td-empty", fmt("ThreatDefence file %s has no indicators", source));
		return;
		}
	td_rows = td_pending;
	td_pending = vector();
	td_apply(td_rows);
	}

event OffensiveAgency::td_timer()
	{
	td_load();
	if ( ! reading_traces() )
		schedule refresh_interval { OffensiveAgency::td_timer() };
	}

event OffensiveAgency::sources_ready()
	{
	if ( td_running )
		return;
	td_running = T;
	event OffensiveAgency::td_timer();
	}

event OffensiveAgency::td_reapply()
	{
	td_reapply_scheduled = F;
	if ( |td_rows| > 0 )
		td_apply(td_rows);
	}

function td_on_filter_change(ID: string, new_value: any): any
	{
	if ( is_authority() && td_running && ! td_reapply_scheduled )
		{
		td_reapply_scheduled = T;
		schedule 0 sec { OffensiveAgency::td_reapply() };
		}
	return new_value;
	}

event OffensiveAgency::td_reload()
	{
	if ( td_file == "" )
		{
		# Switched off: withdraw everything we inserted.
		for ( key in td_inserted )
			{
			local kv = split_string1(key, /\|/);
			Intel::remove([$indicator=kv[1], $indicator_type=kv[0] == "ip" ? Intel::ADDR : Intel::DOMAIN,
			               $meta=[$source=td_intel_source]], F);
			}
		td_inserted = table();
		td_rows = vector();
		td_hosts = table();
		td_domains = table();
		return;
		}
	td_load();
	}

function td_on_file_change(ID: string, new_value: any): any
	{
	# Runs before the option takes its new value: act on the next tick.
	if ( is_authority() && td_running )
		schedule 0 sec { OffensiveAgency::td_reload() };
	return new_value;
	}

event zeek_init()
	{
	for ( id in set("OffensiveAgency::td_min_confidence", "OffensiveAgency::td_ignore_indicators",
	                "OffensiveAgency::td_skip_context", "OffensiveAgency::ignore_indicators",
	                "OffensiveAgency::watch_ips", "OffensiveAgency::watch_domains") )
		Option::set_change_handler(id, td_on_filter_change);
	Option::set_change_handler("OffensiveAgency::td_file", td_on_file_change);
	}
