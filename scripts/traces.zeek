##! Behavioural signatures of offensive AI agents, evaluated on workers.
##!
##! Source: the "traces" section of https://www.offensive.agency/api/v1/agents/<slug>
##! (what each agent leaves in its targets' logs). Only traces that are
##! specific to an agent made it into this table; generic ones such as
##! "python-requests plus ffuf from one source" or the stock nuclei/sqlmap
##! User-Agents were deliberately left out, because they would fire on
##! every ordinary scanner. A few borderline ones are kept but marked
##! weak: they are logged, never noticed on their own.
##!
##! Roles decide the notice:
##!   attack   - the agent attacking a target. Inbound: Agent_Activity_Inbound;
##!              from a local host: Agent_Running_Locally.
##!   operator - the agent phoning home (updates, telemetry, model APIs) or
##!              fetching on its operator's behalf. From a local host:
##!              Agent_Running_Locally; inbound: logged only.
##!   implant  - C2 beacons of an agent's built-in implant.
##!   webshell - an agent driving a web shell.
##!              Both: Agent_Implant_Or_Webshell, either direction.
##!   oast     - lookups of out-of-band callback domains from a local host:
##!              OAST_Callback_Lookup.
##!
##! A signature can be switched off at runtime by adding its id to the
##! OffensiveAgency::disabled_signatures option.

@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load ./main

module OffensiveAgency;

export {
	type Signature: record {
		agent: string;
		## ua, header-name, header-value, uri, method, dns
		field: string;
		## For header-value: the (upper-case) header name to check;
		## empty means any header.
		header: string &default="";
		pat:   pattern;
		role:  string;
		desc:  string;
		weak:  bool &default=F;
	};

	const signatures: table[string] of Signature = {
		# ---------------- User-Agents ----------------
		["artex-enrich-ua"] = [$agent="artex", $field="ua", $role="attack",
			$pat=/(artex|antifox)-enrich\//, $desc="ARTEX asset enrichment probe User-Agent"],
		["artex-norma-ua"] = [$agent="artex", $field="ua", $role="attack",
			$pat=/^norma\/0\.[0-9]+$/, $desc="norma page fetcher of the ARTEX agent SDK"],
		["artex-spa-recon-ua"] = [$agent="artex", $field="ua", $role="attack",
			$pat=/^Mozilla\/5\.0 \(spa-api-recon( spider)?\)$/, $desc="ARTEX spa-api-recon spider"],
		["artex-selfupdate-ua"] = [$agent="artex", $field="ua", $role="operator",
			$pat=/artex-selfupdate/, $desc="ARTEX self-update check"],
		["bugtraceai-ua"] = [$agent="bugtraceai", $field="ua", $role="attack",
			$pat=/[Bb]ug[Tt]race[Aa][Ii]/, $desc="BugTraceAI User-Agent"],
		["cyberstrike-ua"] = [$agent="cyberstrike", $field="ua", $role="attack",
			$pat=/^cyberstrike(\/[^ ]*)?$/, $desc="CyberStrike User-Agent"],
		["cyberstrikeai-webshell-ua"] = [$agent="cyberstrikeai", $field="ua", $role="webshell",
			$pat=/CyberStrikeAI-WebShell\//, $desc="CyberStrikeAI web-shell manager User-Agent"],
		["cyberstrikeai-ua"] = [$agent="cyberstrikeai", $field="ua", $role="operator",
			$pat=/^CyberStrikeAI\/[0-9]/, $desc="CyberStrikeAI client User-Agent"],
		["hexstrike-ua"] = [$agent="hexstrike", $field="ua", $role="attack",
			$pat=/HexStrike-(HTTP-Framework|BrowserAgent)\//, $desc="HexStrike AI User-Agent"],
		["hexstrike-exploit-ua"] = [$agent="hexstrike", $field="ua", $role="attack",
			$pat=/^Mozilla\/5\.0 \(Compatible Exploit\)$/, $desc="HexStrike CVE-exploit User-Agent"],
		["luan1ao-ua"] = [$agent="luan1aoagent", $field="ua", $role="attack",
			$pat=/LuaN1aoAgent\//, $desc="LuaN1aoAgent User-Agent"],
		["luan1ao-fake-chrome-ua"] = [$agent="luan1aoagent", $field="ua", $role="attack",
			$pat=/^Mozilla\/5\.0 \(Macintosh; Intel Mac OS X 10_15_7\) AppleWebKit\/537\.36 Chrome\/124\.0 Safari\/537\.36$/,
			$desc="LuaN1aoAgent fake Chrome (no KHTML, two-part version)"],
		["cai-fake-chrome-ua"] = [$agent="cai", $field="ua", $role="attack",
			$pat=/^Mozilla\/5\.0 \(X11; Linux x86_64\) AppleWebKit\/537\.36 \(KHTML, like Gecko\) Chrome\/124\.0 Safari\/537\.36$/,
			$desc="CAI fake Chrome (two-part version)"],
		["nebula-ua"] = [$agent="nebula", $field="ua", $role="operator",
			$pat=/Nebula\/3 knowledge-source-|Nebula-Terminal\//, $desc="Nebula fetcher/terminal User-Agent"],
		["neurosploit-webshell-ua"] = [$agent="neurosploit", $field="ua", $role="webshell",
			$pat=/NeuroSploit-WebShell\//, $desc="NeuroSploit web-shell manager User-Agent"],
		["neurosploit-ua"] = [$agent="neurosploit", $field="ua", $role="attack",
			$pat=/^NeuroSploit\//, $desc="NeuroSploit scanner User-Agent"],
		["pentagi-ua"] = [$agent="pentagi", $field="ua", $role="operator",
			$pat=/^PentAGI(-Installer)?\//, $desc="PentAGI installer/search User-Agent"],
		["pentest-ai-ua"] = [$agent="pentest-ai", $field="ua", $role="attack",
			$pat=/\+https:\/\/pentestai\.xyz/, $desc="pentest-ai User-Agent"],
		["pentestcode-ua"] = [$agent="pentestcode", $field="ua", $role="operator",
			$pat=/^pentestcode\//, $desc="pentestcode User-Agent"],
		["pentestswarm-ua"] = [$agent="pentestswarm", $field="ua", $role="operator",
			$pat=/^pentestswarm-(cli|webhook)/, $desc="PentestSwarm CLI/webhook User-Agent"],
		["raptor-ua"] = [$agent="raptor", $field="ua", $role="attack",
			$pat=/RAPTOR Security Scanner/, $desc="RAPTOR web module User-Agent"],
		["redamon-ua"] = [$agent="redamon", $field="ua", $role="attack",
			$pat=/RedAmon/, $desc="RedAmon User-Agent"],
		["vigilo-ua"] = [$agent="vigilo", $field="ua", $role="attack",
			$pat=/^Vigilo-Preflight\//, $desc="Vigilo preflight User-Agent"],
		["xalgorix-ua"] = [$agent="xalgorix", $field="ua", $role="operator",
			$pat=/^xalgorix\//, $desc="Xalgorix update-check User-Agent"],
		["z3r0-ua"] = [$agent="z3r0", $field="ua", $role="operator",
			$pat=/^Z3r0-Proxy-Test\//, $desc="Z3r0 egress proxy check"],
		["agentic-bug-hunter-ua"] = [$agent="agentic-bug-hunter", $field="ua", $role="attack",
			$pat=/^agentic-bug-hunter\/|waf-response-analyzer\/|\) Bug-Bounty-Research$/,
			$desc="agentic-bug-hunter User-Agent"],
		# Exactly this string, nothing after 537.36: no real browser sends
		# it, but several unrelated tools copied it. Weak.
		["truncated-chrome-ua"] = [$agent="airecon|pentestagent|cyberstrikeai", $field="ua", $role="attack",
			$pat=/^Mozilla\/5\.0 \(Windows NT 10\.0; Win64; x64\) AppleWebKit\/537\.36$/,
			$desc="truncated Chrome User-Agent used by several agents", $weak=T],

		# Not matched on its own (field "pair"): raised by the pairing check
		# in http_header below, when a weak implant trait comes with the
		# implant's check-in or task-poll request.
		["cyberstrikeai-implant-checkin"] = [$agent="cyberstrikeai", $field="pair", $role="implant",
			$pat=/./, $desc="CyberStrikeAI implant check-in (truncated Chrome User-Agent or X-Session-Token on POST /check_in or GET /tasks?session_id=)"],

		# ---------------- Header names ----------------
		["implant-token-hdr"] = [$agent="cyberstrikeai|neurosploit", $field="header-name", $role="implant",
			$pat=/^X-IMPLANT-TOKEN$/, $desc="C2 beacon header X-Implant-Token"],
		["neurosploit-scan-hdr"] = [$agent="neurosploit", $field="header-name", $role="attack",
			$pat=/^X-NEUROSPLOIT-SCAN$/, $desc="X-NeuroSploit-Scan header"],
		["redamon-ctx-hdr"] = [$agent="redamon", $field="header-name", $role="attack",
			$pat=/^X-REDAMON-CTX$/, $desc="leaked X-Redamon-Ctx header"],
		["pentestswarm-sig-hdr"] = [$agent="pentestswarm", $field="header-name", $role="operator",
			$pat=/^X-PENTESTSWARM-SIGNATURE$/, $desc="PentestSwarm webhook signature header"],

		# ---------------- Header values ----------------
		["cyberstrike-poison-hdr"] = [$agent="cyberstrike", $field="header-value", $role="attack",
			$pat=/mam[0-9a-f]{10}\.poison\.test/, $desc="CyberStrike host-header poisoning canary"],
		["redamon-poison-hdr"] = [$agent="redamon", $field="header-value", $role="attack",
			$pat=/rdmn[0-9a-f]{10}\.redamon-poc\.invalid/, $desc="RedAmon cache-poisoning canary"],
		["pentest-ai-reqid-hdr"] = [$agent="pentest-ai", $field="header-value", $header="X-REQUEST-ID",
			$role="attack", $pat=/^7a3f9c21-4b08-4e11-9c02-/, $desc="pentest-ai fixed X-Request-ID prefix"],
		["pentestswarm-override-hdr"] = [$agent="pentestswarm", $field="header-value", $role="attack",
			$pat=/vV9x-nonexistent-9271/, $desc="PentestSwarm URL-override probe"],
		["shannon-boundary"] = [$agent="shannon", $field="header-value", $header="CONTENT-TYPE",
			$role="attack", $pat=/shannonPhp2shellProbe/, $desc="Shannon PHP-to-shell multipart probe"],
		["bugtrace-cookie"] = [$agent="bugtraceai", $field="header-value", $header="COOKIE",
			$role="attack", $pat=/QlRBSV9kZXNlcl9/, $desc="BugTraceAI deserialisation probe cookie"],
		# boundary=VERIFY/MISMATCH: ARTEX's embedded PHP PoC, which also
		# exists as a public exploit. Weak.
		["artex-php-boundary"] = [$agent="artex", $field="header-value", $header="CONTENT-TYPE",
			$role="attack", $pat=/boundary=(VERIFY|MISMATCH)$/,
			$desc="PHP_SESSION_UPLOAD_PROGRESS PoC boundary (ARTEX or public PoC)", $weak=T],

		# ---------------- URI markers ----------------
		["hexstrike-xss-uri"] = [$agent="hexstrike", $field="uri", $role="attack",
			$pat=/hexstrikeXSSTest123/, $desc="HexStrike XSS marker"],
		["bugtrace-uri"] = [$agent="bugtraceai", $field="uri", $role="attack",
			$pat=/bugtraceomni7x9z|BT7331[A-E]|BUGTRACE(AI_7x7|-XSS-CONFIRMED|_XXE_CONFIRMED)|pp_bugtrace_12345|btai_baseline_test|BTAIRCE7331|HACKED BY BUGTRACEAI/,
			$desc="BugTraceAI probe marker"],
		["pentestswarm-uri"] = [$agent="pentestswarm", $field="uri", $role="attack",
			$pat=/evil\.pentestswarm\.invalid|nx_nonexistent_zzq|nx_wrong_zzq|zzq9xk3n7t2wq1/,
			$desc="PentestSwarm probe marker"],
		["pentest-ai-redirect-uri"] = [$agent="pentest-ai", $field="uri", $role="attack",
			$pat=/r\.pentestai\.xyz\//, $desc="pentest-ai redirect probe"],
		["xalgorix-uri"] = [$agent="xalgorix", $field="uri", $role="attack",
			$pat=/xalgorix(_probe|-nonexistent-|-missing-|-xxe-)/, $desc="Xalgorix probe marker"],
		["redamon-cachebuster-uri"] = [$agent="redamon", $field="uri", $role="attack",
			$pat=/[?&]rdmncb=/, $desc="RedAmon cache-buster parameter"],

		# ---------------- HTTP methods ----------------
		["cyberstrike-csprobe"] = [$agent="cyberstrike", $field="method", $role="attack",
			$pat=/^CSPROBE$/, $desc="CyberStrike CSPROBE method"],

		# ---------------- DNS / TLS SNI names ----------------
		["pentagi-update-dns"] = [$agent="pentagi", $field="dns", $role="operator",
			$pat=/^update\.pentagi\.com$/, $desc="PentAGI update check"],
		["cyberstrike-api-dns"] = [$agent="cyberstrike", $field="dns", $role="operator",
			$pat=/^(api|app|brain)\.cyberstrike\.io$/, $desc="CyberStrike cloud endpoints"],
		["cai-telemetry-dns"] = [$agent="cai", $field="dns", $role="operator",
			$pat=/^(logs|api)\.aliasrobotics\.com$/, $desc="CAI telemetry/API endpoints"],
		["strix-telemetry-dns"] = [$agent="strix", $field="dns", $role="operator",
			$pat=/^strix\.gateway\.scarf\.sh$/, $desc="Strix telemetry gateway"],
		["redamon-verify-dns"] = [$agent="redamon", $field="dns", $role="attack",
			$pat=/^_redamon-verify\./, $desc="RedAmon domain ownership check"],
		["oast-dnslog"] = [$agent="cyberstrikeai|oast", $field="dns", $role="oast",
			$pat=/(^|\.)dnslog\.cn$/, $desc="dnslog.cn out-of-band callback"],
		["oast-interactsh"] = [$agent="strix|bugtraceai|oast", $field="dns", $role="oast",
			$pat=/\.oast\.(pro|live|site|online|fun|me)$|(^|\.)interact\.sh$/,
			$desc="interactsh out-of-band callback"],
		["oast-pentest-ai"] = [$agent="pentest-ai", $field="dns", $role="oast",
			$pat=/(^|\.)r\.pentestai\.xyz$/, $desc="pentest-ai redirect probe callback"],
	} &redef;
}

global rebuild_index: event();

# CyberStrikeAI implant traits (internal/c2/payload_builder.go, beacon.go.tmpl,
# payload_oneliner.go): each is weak alone, the pair is the implant.
const implant_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
const implant_session_token = /^[0-9a-fA-F]{64}$/;

## T if this request is a CyberStrikeAI implant check-in or task poll.
function implant_request(c: connection): bool
	{
	if ( ! c?$http || ! c$http?$method || ! c$http?$uri )
		return F;
	local m = c$http$method;
	local u = c$http$uri;
	return (m == "POST" && /^\/check_in(\?|$)/ in u) ||
	       (m == "GET" && /^\/tasks\?session_id=/ in u);
	}

# Signatures split by field for fast dispatch, plus one union pattern per
# field so the common case (no match) costs a single regex test.
global by_field: table[string] of set[string];
global any_pat: table[string] of pattern;

function build_index()
	{
	by_field = table();
	any_pat = table();
	for ( sid, sig in signatures )
		{
		if ( sid in disabled_signatures )
			next;
		if ( sig$field !in by_field )
			{
			by_field[sig$field] = set();
			any_pat[sig$field] = sig$pat;
			}
		else
			any_pat[sig$field] = any_pat[sig$field] | sig$pat;
		add by_field[sig$field][sid];
		}
	}

function on_disabled_change(ID: string, new_value: any): any
	{
	# The handler runs before the option takes its new value; rebuild
	# on the next tick.
	schedule 0 sec { OffensiveAgency::rebuild_index() };
	return new_value;
	}

event OffensiveAgency::rebuild_index()
	{
	build_index();
	}

event zeek_init()
	{
	build_index();
	Option::set_change_handler("OffensiveAgency::disabled_signatures", on_disabled_change);
	}

function role_rank(r: string): count
	{
	switch ( r ) {
	case "implant", "webshell": return 4;
	case "attack": return 3;
	case "operator": return 2;
	case "oast": return 1;
	}
	return 0;
	}

## Find the best signature of `field` matching `value` (and header name).
function match_sig(field: string, value: string, hname: string): string
	{
	if ( field !in any_pat || any_pat[field] !in value )
		return "";

	local best = "";
	for ( sid in by_field[field] )
		{
		local sig = signatures[sid];
		if ( sig$header != "" && sig$header != hname )
			next;
		if ( sig$pat !in value )
			next;
		if ( best == "" || role_rank(sig$role) > role_rank(signatures[best]$role) ||
		     (signatures[best]$weak && ! sig$weak) )
			best = sid;
		}
	return best;
	}

function emit(c: connection, sid: string, kind: string, seen_where: string)
	{
	local sig = signatures[sid];
	local dir = direction_of(c$id);
	local h = Hit($ts=network_time(), $uid=c$uid, $id=c$id, $kind=kind,
	              $indicator=sid, $seen_where=seen_where, $direction=dir,
	              $agents=sig$agent, $role=sig$role, $sig_desc=sig$desc,
	              $weak=sig$weak);

	if ( dir == "inbound" )
		{
		h$local_host = c$id$resp_h;
		h$remote_host = c$id$orig_h;
		}
	else
		{
		h$local_host = c$id$orig_h;
		h$remote_host = c$id$resp_h;
		}

	report(h);
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
	{
	if ( ! watch_behaviour )
		return;

	local sid = match_sig("method", method, "");
	if ( sid != "" )
		emit(c, sid, "method", method);

	sid = match_sig("uri", unescaped_URI, "");
	if ( sid == "" && unescaped_URI != original_URI )
		sid = match_sig("uri", original_URI, "");
	if ( sid != "" )
		emit(c, sid, "uri", "HTTP::URI");
	}

event http_header(c: connection, is_orig: bool, original_name: string,
                  name: string, value: string)
	{
	if ( ! is_orig || ! watch_behaviour )
		return;

	local sid = "";

	# Two weak traits of the CyberStrikeAI implant become one strong
	# finding when they come with its check-in/task-poll request.
	if ( ((name == "USER-AGENT" && value == implant_ua) ||
	      (name == "X-SESSION-TOKEN" && implant_session_token in value)) &&
	     "cyberstrikeai-implant-checkin" !in disabled_signatures &&
	     implant_request(c) )
		{
		if ( name == "USER-AGENT" )
			emit(c, "cyberstrikeai-implant-checkin", "ua", value);
		else
			emit(c, "cyberstrikeai-implant-checkin", "header", name);
		return;
		}

	if ( name == "USER-AGENT" )
		{
		sid = match_sig("ua", value, name);
		if ( sid != "" )
			emit(c, sid, "ua", value);
		return;
		}

	sid = match_sig("header-name", name, name);
	if ( sid != "" )
		{
		emit(c, sid, "header", name);
		return;
		}

	sid = match_sig("header-value", value, name);
	if ( sid != "" )
		emit(c, sid, "header", name);
	}

function check_name(c: connection, name: string, kind: string)
	{
	local sid = match_sig("dns", to_lower(name), "");
	if ( sid == "" )
		return;
	local role = signatures[sid]$role;
	if ( role == "oast" && ! watch_oast )
		return;
	if ( role != "oast" && ! watch_behaviour )
		return;
	# Only names looked up or contacted by local clients matter; the one
	# exception is the RedAmon ownership check, which arrives as an
	# inbound query to your own authoritative servers.
	if ( ! Site::is_local_addr(c$id$orig_h) && role != "attack" )
		return;
	emit(c, sid, kind, to_lower(name));
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count,
                  original_query: string)
	{
	check_name(c, query, "dns");
	}

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec)
	{
	if ( ! is_client )
		return;
	for ( i in names )
		check_name(c, names[i], "sni");
	}
