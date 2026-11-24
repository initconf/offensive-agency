=================================================================================
offensive-agency: detect offensive AI agents on your network
=================================================================================

`offensive.agency <https://www.offensive.agency/>`_ tracks Internet-exposed
consoles of offensive AI agents (ARTEX, CyberStrikeAI, PentAGI, HexStrike AI,
RedAmon, Strix, Cairn, BugTraceAI, ...). Data by `ONYPHE <https://www.onyphe.io/>`_,
free, no API key. This package turns that feed into precise, cluster-safe Zeek
notices.

Following functionality is provided by the package
--------------------------------------------------
::

        1) Feed sync: the manager polls the feed every 30 min with conditional
           (ETag) requests, filters it for precision, and keeps the Intel
           framework in sync (inserts new indicators, removes ones that left
           the feed). Workers match at line rate.
        2) IP and domain matching, direction-aware: established TCP to/from a
           listed host; DNS queries, TLS SNI and HTTP Host for listed domains.
        3) Behavioural signatures from each agent's documented traces:
           User-Agents, C2 implant headers, web-shell managers, payload
           markers, update/telemetry endpoints, OAST callback lookups.
        4) Your own address in the feed: Local_Host_Listed.
        5) Feed health: Feed_Problem on repeated fetch failures or stale data.

Installation
------------
::

        zkg install offensive-agency
        # or, from a checkout, in local.zeek:
        @load /path/to/offensive-agency/scripts

Requirements: Zeek >= 8.0, ``curl`` >= 7.68 on the manager (for ETag support),
outbound HTTPS from the manager to www.offensive.agency (or see *Air-gapped
sensors* below). Set ``Site::local_nets``: every decision depends on direction.

Configuration (Config framework, no redef)
------------------------------------------

All tunables are ``option`` values. Copy ``scripts/offensive-agency.cfg.example``,
uncomment what you need, and register it::

        redef Config::config_files += { "/etc/zeek/offensive-agency.cfg" };

Changes take effect without restarting Zeek; in a cluster the manager reads
the file and pushes values to all nodes. Filtering options re-apply the cached
feed immediately. Most useful knobs:

=================================  ==========  ===========================================
option                             default     purpose
=================================  ==========  ===========================================
``min_level``                      confirmed   ``probable`` = one fingerprint family is enough
``include_cdn_ips``                F           CDN fronts serve thousands of unrelated sites
``max_ip_age``                     7 days      last seen within N of the feed's newest day
``max_cloud_ip_age``               3 days      cloud IPs get reassigned quickly
``ignore_hosts``                   {}          your scanners / pentest boxes / researchers
``ignore_indicators``              {}          feed IPs or domains never to watch
``inbound_ignore_ports``           {}          inbound contacts logged but not noticed
``disabled_signatures``            {}          behavioural signature ids to turn off
``dedup_interval``                 1 day       one log row + notice per finding per window
``refresh_interval``               30 min      feed poll period (304 when nothing changed)
``feed_file``                      ""          read a local NDJSON copy instead of HTTP
=================================  ==========  ===========================================

Notices
-------

================================  ============================================================  ===========
Notice                            Meaning                                                        dedup key
================================  ============================================================  ===========
Outbound_To_Agent_Host            local host connected to a listed agent host (msg says when     local+remote
                                  it was the agent's console port, and co-hosted C2)
Inbound_From_Agent_Host           listed host completed a TCP connection to you (or appeared     remote
                                  in X-Forwarded-For)
Agent_Domain_Contact              local client resolved / SNI / Host of a listed agent domain    local+domain
Agent_Activity_Inbound            inbound HTTP carries an agent signature                         agent+remote
Agent_Running_Locally             a local host emits an agent's signature or calls its update     agent+local
                                  / telemetry endpoints: someone runs an agent inside
Agent_Implant_Or_Webshell         built-in C2 beacon (X-Implant-Token) or agent web-shell         agent+hosts
                                  manager: treat as a full intrusion
OAST_Callback_Lookup              local host resolved dnslog.cn / interactsh: a blind             service+local
                                  injection probably landed
Local_Host_Listed                 one of YOUR addresses runs an exposed agent console             address
Feed_Problem                      fetch failures, empty/shrunk feed, stale data                   problem
================================  ============================================================  ===========

``$src`` is the address to act on: the remote end for inbound findings, the
local host otherwise. ``$sub`` carries the feed context (network type, ASN,
country, co-hosted C2 such as Sliver, first/last seen, link to the host page).

Example::

        OffensiveAgency::Outbound_To_Agent_Host  10.1.1.5 connected to 45.33.1.10:8787/tcp on
          its agent console port, a host running an exposed offensive AI agent (artex:confirmed)
          sub: net=hosting AS64500 NL Example Hosting co-hosted C2=Sliver seen=2026-11-10..2026-11-24
               https://www.offensive.agency/host/45.33.1.10

Every finding, noticed or not, is in ``offensive_agency.log`` (kind, indicator,
direction, local/remote host, agents, role, context, note). Intel matches also
appear in the standard ``intel.log`` with source ``offensive.agency``.

How false positives are kept down
---------------------------------
::

        - Only "confirmed" detections (two independent fingerprint families).
        - Shared CDN fronts are never watched by IP (their domains still are).
        - Cloud addresses age out after 3 days; everything after the 7-day
          active window. Ages are measured against the feed's newest day.
        - IPs match on ESTABLISHED TCP only: SYN scans and backscatter from
          listed hosts never fire.
        - Transit traffic (neither end local) is logged, never noticed.
        - Behavioural signatures were curated from the agents' traces: generic
          traits (stock nuclei/sqlmap UAs, python-requests bursts, PentAGI's
          28000-29999 return ports) were left out. Borderline ones (the
          truncated "...AppleWebKit/537.36" UA, the public PHP-PoC boundary)
          are marked weak: logged, never noticed.
        - One notice per logical finding per day, decided on a single node.
        - Your own listed hosts are reported, never inserted as indicators.
        - A feed that shrinks by more than half is applied additively only.
        - Removals use purge_indicator=F: the same IP from another intel
          source (MISP, ...) is untouched.

Replay check: two LBL captures (about 512k connections, 6.5k HTTP requests)
produced zero findings with the live feed.

Cluster design
--------------
::

        manager:  fetch (Exec+curl, ETag) -> parse (from_json) -> filter
                  -> Intel::insert / Intel::remove ---------------------+
                                                                        |  Intel framework
        workers:  min_data_store match (conn/DNS/SNI/Host) <------------+  distribution
                  behavioural signatures (http_header, dns_request, SNI)
                     |                     |
                     | Intel::match_remote | OffensiveAgency::hit (pre-filtered per worker)
                     v                     v
        manager:  decide + dedup + Log::write + NOTICE   (exactly once)

All decisions happen on the manager: Intel::match is delivered there anyway,
the feed metadata used for enrichment lives there, and hit volume is bounded by
the feed and signature set rather than by traffic. Standalone (``zeek -r``)
runs the same code in one process.

The manager caches the feed and its ETag in ``state_dir``; after a restart it
loads the cached copy immediately (works even if the API is down), then does a
conditional refresh.

Air-gapped sensors
------------------
Fetch on a connected host and copy the file over (cron)::

        curl -sS -o hosts.ndjson https://www.offensive.agency/api/v1/feeds/hosts.ndjson

then set ``OffensiveAgency::feed_file /path/to/hosts.ndjson``; it is re-read
every ``refresh_interval``.

LBL add-on
----------
Not loaded by default. At LBL::

        @load offensive-agency
        @load offensive-agency/lbl

Site settings (authorised scanners in ignore_hosts, never-drop nets) live in
a config file kept outside the package. The package ships only
``scripts/lbl/lbl.cfg.example`` with placeholder addresses; copy it, fill it
in, and register it in local.zeek::

        redef Config::config_files += { "/path/to/lbl.cfg" };

Host-specific values such as ``state_dir`` go in a per-host override config
file.

The add-on also installs a notice policy: ACTION_ALARM for every finding; ACTION_EMAIL for implant,
local-listed, running-locally, outbound, domain, OAST and feed problems;
ACTION_DROP for external inbound sources only when ``lbl_drop_inbound`` is T.
Set that in a separate site override config file (never in the site config file as well:
the Config framework does not order files). Drops are carried out by the
existing ``lbl.drop-action.zeek``.

Tests
-----
::

        cd tests && btest

Standalone TSV + JSON, Config-file options, feed failure, LBL add-on, and a
real ZeroMQ cluster (manager, proxy, two workers both replaying the same trace;
every finding must still appear exactly once). The trace is synthetic and is
regenerated by ``tests/Traces/make-trace.py`` (scapy).

Attribution
-----------
Feed data: offensive.agency, data by ONYPHE. Free to use; please credit both.
