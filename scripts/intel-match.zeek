##! Turn Intel framework matches on this feed's indicators into hits.
##!
##! The Intel seen scripts loaded here run on the workers. A match on a
##! worker is forwarded by the Intel framework to the manager, which raises
##! Intel::match with the full item metadata; that handler runs on the
##! manager (or standalone process) only.
##!
##! Noise properties inherited from the seen scripts:
##!  - IPs match only on ESTABLISHED TCP connections (both sides completed
##!    the handshake). Unanswered scans and backscatter from listed hosts
##!    never match.
##!  - Domains match on DNS queries, TLS SNI and the HTTP Host header.

@load base/frameworks/intel
@load policy/frameworks/intel/seen/conn-established
@load policy/frameworks/intel/seen/dns
@load policy/frameworks/intel/seen/ssl
@load policy/frameworks/intel/seen/http-headers
@load ./main
@load ./threatdefence

module OffensiveAgency;

# Carry the connection identity to the manager explicitly. Seen$conn is a
# full connection record; we only need the 4-tuple and uid, and we do not
# want to depend on how a cluster backend serializes connection records.
redef record Intel::Seen += {
	oa_id:  conn_id &optional;
	oa_uid: string  &optional;
};

hook Intel::seen_policy(s: Intel::Seen, found: bool)
	{
	# Runs for matches of EVERY intel source, so stay defensive: some
	# seen paths hand over a connection record without a uid.
	if ( found && s?$conn )
		{
		s$oa_id = s$conn$id;
		if ( s$conn?$uid )
			s$oa_uid = s$conn$uid;
		else if ( s?$uid )
			s$oa_uid = s$uid;
		}
	}

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	if ( ! is_authority() )
		return;

	# offensive.agency wins when both sources list the indicator; the
	# ThreatDefence context is appended below.
	local agents = "";
	local src = "";
	for ( it in items )
		{
		if ( it$meta$source == intel_source )
			{
			agents = it$meta?$oa_agents ? it$meta$oa_agents : it$meta$desc;
			src = intel_source;
			break;
			}
		if ( it$meta$source == td_intel_source && it$meta?$oa_agents )
			{
			agents = it$meta$oa_agents;
			src = td_intel_source;
			}
		}

	if ( agents == "" )
		return;

	if ( ! s?$oa_id )
		return;

	local id = s$oa_id;
	local h = Hit($ts=network_time(), $id=id, $agents=agents, $kind="",
	              $seen_where=cat(s$where), $indicator=s$indicator);
	if ( s?$oa_uid )
		h$uid = s$oa_uid;
	if ( src == td_intel_source )
		h$source = td_intel_source;
	local td_ctx = "";

	if ( s$indicator_type == Intel::ADDR )
		{
		if ( ! watch_ips )
			return;
		local ip = to_addr(s$indicator);
		h$kind = "ip";
		h$role = "infra";
		h$remote_host = ip;

		if ( s$where == Conn::IN_ORIG || s$where == HTTP::IN_X_FORWARDED_FOR_HEADER )
			{
			h$direction = "inbound";
			h$local_host = id$resp_h;
			}
		else if ( s$where == Conn::IN_RESP )
			{
			h$direction = "outbound";
			h$local_host = id$orig_h;
			}
		else
			{
			# Some other place an address showed up: log, no notice.
			h$direction = "other";
			h$local_host = id$orig_h;
			}

		# A listed host talking to another non-local host is transit
		# traffic, not something that concerns this site.
		if ( ! Site::is_local_addr(h$local_host) )
			h$direction = "transit";

		if ( ip in feed_hosts )
			h$context = feed_hosts[ip]$context;
		if ( ip in td_hosts )
			td_ctx = td_hosts[ip];
		}
	else if ( s$indicator_type == Intel::DOMAIN )
		{
		if ( ! watch_domains )
			return;
		local dn = to_lower(s$indicator);
		h$kind = "domain";
		h$role = "infra";
		h$indicator = dn;
		h$local_host = id$orig_h;
		h$remote_host = id$resp_h;
		h$direction = direction_of(id);

		# Only local clients are interesting (an external resolver
		# querying our authoritative servers for it is not).
		if ( ! Site::is_local_addr(id$orig_h) )
			return;

		if ( dn in feed_domains )
			h$context = feed_domains[dn]$context;
		if ( dn in td_domains )
			td_ctx = td_domains[dn];
		}
	else
		return;

	if ( td_ctx != "" )
		h$context = h?$context ? fmt("%s; %s", h$context, td_ctx) : td_ctx;

	event OffensiveAgency::hit(h);
	}
