##! Feed management: fetch, parse, filter, and sync into the Intel framework.
##!
##! Runs only on the authoritative node (manager, or the standalone
##! process). Indicators are inserted with Intel::insert, which the Intel
##! framework distributes to every worker's minimal data store; removals
##! propagate the same way. Matching therefore happens on the workers at
##! line rate, and Intel::match comes back to the manager (intel-match.zeek).
##!
##! Update cycle (every refresh_interval):
##!   1. curl the feed with If-None-Match (ETag). 304 = nothing to do.
##!   2. On 200, atomically replace the on-disk cache, then read it.
##!   3. Parse each NDJSON line with from_json, apply the noise filters,
##!      and diff against the indicators currently inserted:
##!      new/changed -> Intel::insert, gone -> Intel::remove.
##!
##! Safety: a download that parses to far fewer hosts than we already have
##! (truncated transfer, upstream incident) is applied additively only --
##! nothing is removed -- and raises Feed_Problem. Our removals use
##! purge_indicator=F, so the same IP or domain supplied by another intel
##! source (e.g. MISP) is left untouched.

@load base/frameworks/intel
@load base/utils/exec
@load ./main

module OffensiveAgency;

export {
	## Agent entry inside a host record of the feed.
	type FeedAgent: record {
		slug:   string;
		name:   string &optional;
		level:  string;
		ports:  vector of count &optional;
	};

	type FeedNetwork: record {
		asn:     string &optional;
		org:     string &optional;
		country: string &optional;
		kind:    string &optional;
	};

	type FeedDomain: record {
		name:   string;
		agents: table[string] of string &optional;
	};

	type FeedCohosting: record {
		c2: vector of string &optional;
	};

	## One line of hosts.ndjson. Unknown keys are ignored by from_json.
	type FeedHost: record {
		ip:         addr;
		active:     bool &default=T;
		first_seen: string &default="";
		last_seen:  string &default="";
		agents:     vector of FeedAgent;
		network:    FeedNetwork &optional;
		domains:    vector of FeedDomain &optional;
		cohosting:  FeedCohosting &optional;
	};

	## Force a fetch now (e.g. from a broker/zeekctl hook or a test).
	global refresh: event();
}

# Intel metadata: where an analyst can read more about the indicator.
redef record Intel::MetaData += {
	oa_agents: string &optional;
};

type Line: record {
	s: string;
};

# --- state on the authoritative node ---------------------------------------

## Items we currently have inserted, keyed by "ip|<addr>" / "dom|<name>",
## with a fingerprint of their metadata to detect changes.
global inserted: table[string] of string;

## Last successfully parsed feed, kept so an option change can be
## re-applied without refetching.
global last_hosts: vector of FeedHost;
global pending_hosts: vector of FeedHost;
global pending_bad = 0;

global busy = F;
global load_seq = 0;
global current_load = "";
global consecutive_failures = 0;
global last_success: time = double_to_time(0.0);
global newest_day: time = double_to_time(0.0);
global reapply_scheduled = F;
global started = F;

global apply: function(hosts: vector of FeedHost);

function cache_body(): string  { return fmt("%s/hosts.ndjson", state_dir); }
function cache_etag(): string  { return fmt("%s/hosts.etag", state_dir); }

function level_ok(level: string): bool
	{
	if ( min_level == "probable" )
		return level == "confirmed" || level == "probable";
	return level == "confirmed";
	}

function feed_problem(what: string, detail: string)
	{
	report(Hit($ts=network_time(), $kind="feed", $indicator=what,
	           $context=detail, $role="infra"));
	}

# --- reading a feed file -----------------------------------------------------

event OffensiveAgency::feed_line(desc: Input::EventDescription, tpe: Input::Event, s: string)
	{
	if ( desc$name != current_load )
		return;
	if ( |s| == 0 )
		return;

	local r = from_json(s, FeedHost);
	if ( ! r$valid )
		{
		++pending_bad;
		return;
		}
	pending_hosts += (r$v as FeedHost);
	}

function load_file(path: string)
	{
	if ( file_size(path) < 0 )
		{
		busy = F;
		feed_problem("missing-file", fmt("feed file %s does not exist", path));
		return;
		}

	++load_seq;
	current_load = fmt("offensive-agency-feed-%d", load_seq);
	pending_hosts = vector();
	pending_bad = 0;

	Input::add_event([$source=path, $name=current_load, $reader=Input::READER_RAW,
	                  $mode=Input::MANUAL, $fields=Line, $want_record=F,
	                  $ev=OffensiveAgency::feed_line]);
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name != current_load )
		return;

	Input::remove(name);
	current_load = "";
	busy = F;

	if ( |pending_hosts| == 0 )
		{
		++consecutive_failures;
		feed_problem("empty", fmt("feed %s parsed to 0 hosts (%d unparsable lines)",
		                          source, pending_bad));
		return;
		}

	if ( pending_bad > 0 )
		Reporter::info(fmt("offensive-agency: %d unparsable feed lines in %s",
		                   pending_bad, source));

	consecutive_failures = 0;
	last_success = current_time();
	last_hosts = pending_hosts;
	pending_hosts = vector();
	apply(last_hosts);
	}

# --- fetching -----------------------------------------------------------------

function fetch()
	{
	if ( busy )
		return;
	busy = T;

	if ( feed_file != "" )
		{
		load_file(feed_file);
		return;
		}

	local body = cache_body();
	local etag = cache_etag();
	local tmp_body = body + ".tmp";
	local tmp_etag = etag + ".tmp";

	local curl = fmt("%s -sS -L --compressed -m %.0f -A %s -w '%%{http_code}' --etag-save %s -o %s",
	                 safe_shell_quote(curl_path), interval_to_double(fetch_timeout),
	                 safe_shell_quote(fmt("zeek-offensive-agency/%s", version)),
	                 safe_shell_quote(tmp_etag), safe_shell_quote(tmp_body));

	# Only send the ETag if we still have the body it describes.
	if ( file_size(etag) > 0 && file_size(body) > 0 )
		curl = fmt("%s --etag-compare %s", curl, safe_shell_quote(etag));

	curl = fmt("%s %s", curl, safe_shell_quote(feed_url));

	# Print "<curl exit> <http code>"; on a complete 200, atomically move
	# the new body and ETag into place.
	local cmd = fmt("mkdir -p %s; code=$(%s); rc=$?; echo \"$rc $code\"; " +
	                "if [ \"$rc\" = 0 ] && [ \"$code\" = 200 ] && [ -s %s ]; then " +
	                "mv -f %s %s && mv -f %s %s; fi; rm -f %s %s",
	                safe_shell_quote(state_dir), curl, safe_shell_quote(tmp_body),
	                safe_shell_quote(tmp_body), safe_shell_quote(body),
	                safe_shell_quote(tmp_etag), safe_shell_quote(etag),
	                safe_shell_quote(tmp_body), safe_shell_quote(tmp_etag));

	when [cmd, body] ( local res = Exec::run([$cmd=cmd]) )
		{
		local status = "";
		if ( res?$stdout && |res$stdout| > 0 )
			status = res$stdout[|res$stdout| - 1];

		local parts = split_string(status, / /);
		local rc = |parts| == 2 ? parts[0] : "?";
		local code = |parts| == 2 ? parts[1] : "?";

		if ( rc == "0" && code == "304" )
			{
			busy = F;
			consecutive_failures = 0;
			last_success = current_time();
			return;
			}

		if ( rc == "0" && code == "200" )
			{
			load_file(body);
			return;
			}

		busy = F;
		++consecutive_failures;
		local err = res?$stderr ? join_string_vec(res$stderr, " ") : "";
		Reporter::warning(fmt("offensive-agency: fetch of %s failed (curl rc=%s http=%s) %s",
		                      feed_url, rc, code, err));

		if ( consecutive_failures >= failures_before_notice )
			feed_problem("fetch-failed",
			             fmt("%d consecutive failures fetching %s (curl rc=%s http=%s); using cached data",
			                 consecutive_failures, feed_url, rc, code));
		}
	}

event OffensiveAgency::refresh()
	{
	if ( ! is_authority() )
		return;
	fetch();
	}

event OffensiveAgency::refresh_timer()
	{
	fetch();

	# When replaying a trace, network time jumps from 0 to the first
	# packet's timestamp and any interval timer would fire at once. One
	# load is all a trace replay needs.
	if ( ! reading_traces() )
		schedule refresh_interval { OffensiveAgency::refresh_timer() };
	}

event OffensiveAgency::health_check()
	{
	schedule 1 hr { OffensiveAgency::health_check() };

	# Wall-clock checks make no sense when replaying a trace.
	if ( reading_traces() )
		return;

	local now = current_time();
	if ( last_success != double_to_time(0.0) && now - last_success > stale_after )
		feed_problem("no-update", fmt("no successful update since %s", last_success));

	if ( newest_day != double_to_time(0.0) && now - newest_day > stale_after + 1 day )
		feed_problem("stale-data", fmt("newest observation in the feed is from %s",
		                               strftime("%Y-%m-%d", newest_day)));
	}

# --- filtering and applying ---------------------------------------------------

function day(s: string): time
	{
	if ( s == "" )
		return double_to_time(0.0);
	return strptime("%Y-%m-%d", s);
	}

function join_set(s: set[string]): string
	{
	local v: vector of string;
	for ( x in s )
		v += x;
	sort(v, strcmp);
	return join_string_vec(v, ",");
	}

function host_context(h: FeedHost): string
	{
	local parts: vector of string;
	if ( h?$network )
		{
		local n = h$network;
		parts += fmt("net=%s %s %s %s", n?$kind ? n$kind : "-", n?$asn ? n$asn : "-",
		             n?$country ? n$country : "-", n?$org ? n$org : "-");
		}
	if ( h?$cohosting && h$cohosting?$c2 && |h$cohosting$c2| > 0 )
		parts += fmt("co-hosted C2=%s", join_string_vec(h$cohosting$c2, "|"));
	parts += fmt("seen=%s..%s", h$first_seen, h$last_seen);
	parts += fmt("https://www.offensive.agency/host/%s", h$ip);
	return join_string_vec(parts, " ");
	}

function sync_item(key: string, indicator: string, t: Intel::Type, ctx: HostCtx,
                   desired: set[string])
	{
	add desired[key];
	local fp = fmt("%s|%s", ctx$agents, ctx$context);
	if ( key in inserted && inserted[key] == fp )
		return;

	inserted[key] = fp;
	Intel::insert([$indicator=indicator, $indicator_type=t,
	               $meta=[$source=intel_source, $desc=ctx$agents, $oa_agents=ctx$agents,
	                      $url=t == Intel::ADDR
	                          ? fmt("https://www.offensive.agency/host/%s", indicator)
	                          : fmt("https://www.offensive.agency/api/v1/domains/%s", indicator)]]);
	}

function apply(hosts: vector of FeedHost)
	{
	local new_hosts: table[addr] of HostCtx;
	local new_domains: table[string] of HostCtx;
	local desired: set[string];

	# The feed's reference day is its newest observation; ages are
	# measured against it, not against wall-clock or trace time.
	local ref = double_to_time(0.0);
	for ( i in hosts )
		{
		local ls = day(hosts[i]$last_seen);
		if ( ls > ref )
			ref = ls;
		}
	newest_day = ref;

	for ( i in hosts )
		{
		local h = hosts[i];
		if ( ! h$active )
			next;

		# NB: Zeek locals are function-scoped; a declaration inside a
		# loop WITHOUT an initializer keeps the previous iteration's
		# value. Always initialize.
		local agents: set[string] = set();
		local all_agents: set[string] = set();
		local ports: set[port] = set();
		for ( j in h$agents )
			{
			local a = h$agents[j];
			add all_agents[fmt("%s:%s", a$slug, a$level)];
			if ( ! level_ok(a$level) )
				next;
			add agents[fmt("%s:%s", a$slug, a$level)];
			if ( a?$ports )
				for ( k in a$ports )
					add ports[count_to_port(a$ports[k], tcp)];
			}

		local kind = (h?$network && h$network?$kind) ? h$network$kind : "";
		local ctx = HostCtx($agents=join_set(agents), $ports=ports, $kind=kind,
		                    $context=host_context(h));

		# One of ours is listed: always report, whatever the level or
		# network type, and never insert it as an indicator (every
		# internal connection to it would match).
		if ( Site::is_local_addr(h$ip) )
			{
			if ( cat(h$ip) !in ignore_indicators )
				report(Hit($ts=network_time(), $kind="local_listed", $indicator=cat(h$ip),
				           $local_host=h$ip, $agents=join_set(all_agents),
				           $context=host_context(h), $role="infra"));
			next;
			}

		# Domains (from the hosts' ctiurl observations) carry their own
		# per-agent levels. Watched even when the IP is a CDN front.
		if ( watch_domains && h?$domains )
			for ( j in h$domains )
				{
				local d = h$domains[j];
				local dname = to_lower(d$name);
				if ( dname in ignore_indicators )
					next;
				local dag: set[string] = set();
				if ( d?$agents )
					for ( slug, lvl in d$agents )
						if ( level_ok(lvl) )
							add dag[fmt("%s:%s", slug, lvl)];
				if ( |dag| == 0 )
					next;
				new_domains[dname] = HostCtx($agents=join_set(dag), $ports=ports,
				                             $kind=kind, $context=ctx$context,
				                             $domains=dname);
				}

		if ( |agents| == 0 || ! watch_ips )
			next;
		if ( cat(h$ip) in ignore_indicators )
			next;
		if ( kind == "cdn" && ! include_cdn_ips )
			next;

		local age = ref - day(h$last_seen);
		if ( age > max_ip_age )
			next;
		if ( kind == "cloud" && age > max_cloud_ip_age )
			next;

		new_hosts[h$ip] = ctx;
		}

	for ( ip, c in new_hosts )
		sync_item(fmt("ip|%s", ip), cat(ip), Intel::ADDR, c, desired);
	for ( dn, c in new_domains )
		sync_item(fmt("dom|%s", dn), dn, Intel::DOMAIN, c, desired);

	# Removal guard: a feed that shrank by more than half is suspicious
	# (truncated download, upstream outage). Keep what we have.
	local shrink = |inserted| > 100 && |desired| * 2 < |inserted|;
	if ( shrink )
		feed_problem("shrunk", fmt("feed shrank from %d to %d indicators; not removing any",
		                           |inserted|, |desired|));
	else
		{
		local gone: vector of string;
		for ( ikey in inserted )
			if ( ikey !in desired )
				gone += ikey;
		for ( gi in gone )
			{
			local kv = split_string1(gone[gi], /\|/);
			local t = kv[0] == "ip" ? Intel::ADDR : Intel::DOMAIN;
			Intel::remove([$indicator=kv[1], $indicator_type=t,
			               $meta=[$source=intel_source]], F);
			delete inserted[gone[gi]];
			}
		}

	feed_hosts = new_hosts;
	feed_domains = new_domains;

	event OffensiveAgency::feed_updated(|new_hosts|, |new_domains|);
	}

# Re-apply the cached feed when a filtering option changes at runtime.
event OffensiveAgency::reapply()
	{
	reapply_scheduled = F;
	if ( |last_hosts| > 0 )
		apply(last_hosts);
	}

function on_filter_change(ID: string, new_value: any): any
	{
	if ( is_authority() && ! reapply_scheduled )
		{
		reapply_scheduled = T;
		schedule 0 sec { OffensiveAgency::reapply() };
		}
	return new_value;
	}

function on_source_change(ID: string, new_value: any): any
	{
	# Before start() the new value is simply used by the first load.
	if ( is_authority() && started )
		schedule 0 sec { OffensiveAgency::refresh() };
	return new_value;
	}

# Startup is deferred until the Config framework has applied every config
# file: options such as state_dir and feed_file come from those files, and
# zeek_init runs before they are read.
global configs_pending: set[string];

function start()
	{
	if ( started )
		return;
	started = T;

	schedule 1 hr { OffensiveAgency::health_check() };

	# Warm start: load the cached copy from a previous run right away,
	# then let the timer do a conditional fetch shortly after.
	if ( feed_file == "" && file_size(cache_body()) > 0 )
		{
		busy = T;
		load_file(cache_body());
		schedule 5 sec { OffensiveAgency::refresh_timer() };
		return;
		}

	# Cold start (or feed_file mode): load now.
	fetch();

	# When replaying a trace, network time jumps from 0 to the first
	# packet's timestamp and any interval timer would fire at once. One
	# load is all a trace replay needs.
	if ( ! reading_traces() )
		schedule refresh_interval { OffensiveAgency::refresh_timer() };
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name !in configs_pending )
		return;
	delete configs_pending[name];
	if ( |configs_pending| == 0 )
		start();
	}

# Fallback if a config file is missing or unreadable (no end_of_data).
event OffensiveAgency::start_fallback()
	{
	if ( ! started )
		{
		Reporter::warning(fmt("offensive-agency: config files not all read (%s); starting anyway",
		                      configs_pending));
		start();
		}
	}

event zeek_init()
	{
	for ( id in set("OffensiveAgency::min_level", "OffensiveAgency::include_cdn_ips",
	                "OffensiveAgency::max_ip_age", "OffensiveAgency::max_cloud_ip_age",
	                "OffensiveAgency::watch_ips", "OffensiveAgency::watch_domains",
	                "OffensiveAgency::ignore_indicators") )
		Option::set_change_handler(id, on_filter_change);

	Option::set_change_handler("OffensiveAgency::feed_url", on_source_change);
	Option::set_change_handler("OffensiveAgency::feed_file", on_source_change);
	Option::set_change_handler("OffensiveAgency::state_dir", on_source_change);

	if ( ! is_authority() )
		return;

	# Trace replay starts at once: with processing suspended, network
	# time does not advance and a fallback timer could never fire. Option
	# changes from config files are re-applied by the change handlers.
	if ( reading_traces() || |Config::config_files| == 0 )
		{
		start();
		return;
		}

	for ( f in Config::config_files )
		add configs_pending[cat("config-", f)];
	schedule 30 sec { OffensiveAgency::start_fallback() };
	}
