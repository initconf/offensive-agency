# @TEST-DOC: Cluster (manager+proxy+2 workers, ZeroMQ): the manager loads the feed, Intel distributes it, BOTH workers replay the same trace, and every finding is still logged and noticed exactly once (TSV + JSON).
#
# @TEST-REQUIRES: have-zeromq
# @TEST-GROUP: cluster
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: chmod +x ./check-log.sh
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: btest-bg-run manager  "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager  zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run proxy    "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy    zeek -b ../node.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b -C -r $TRACES/offensive-agency.pcap ../worker.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b -C -r $TRACES/offensive-agency.pcap ../worker.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 90
#
# Exactly the standalone result, despite two workers seeing everything:
# @TEST-EXEC: test "$(grep -vc '^#' manager/offensive_agency.log)" = "13"
# @TEST-EXEC: test "$(grep -vc '^#' manager/notice.log)" = "10"
# @TEST-EXEC: zeek-cut kind indicator direction local_host remote_host agents note < manager/offensive_agency.log | sort > hits.txt
# @TEST-EXEC: btest-diff hits.txt
# @TEST-EXEC: zeek-cut note msg src dst < manager/notice.log | sort > notices.txt
# @TEST-EXEC: btest-diff notices.txt
# JSON mirror written by the same Log::write on the logger:
# @TEST-EXEC: test "$(wc -l < manager/json-out/offensive_agency.log)" = "13"
# @TEST-EXEC: grep -q '"note":"OffensiveAgency::Agent_Implant_Or_Webshell"' manager/json-out/offensive_agency.log

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap
@load base/frameworks/cluster
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl

@load offensive-agency/scripts

redef Log::default_rotation_interval = 0sec;
redef Log::flush_interval = 0.01sec;
redef OffensiveAgency::feed_file = getenv("TEST_FILES") + "/feed.ndjson";

# JSON mirror of the package log, to prove filters fan out once.
event zeek_init() &priority=-10
	{
	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return;
	mkdir("json-out");
	local f = Log::get_filter(OffensiveAgency::LOG, "default");
	f$name = "json";
	f$path = "json-out/offensive_agency";
	f$config = table(["use_json"] = "T");
	Log::add_filter(OffensiveAgency::LOG, f);
	}

global finish: event() &is_used;
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_down: set[string] = { "manager" };
global done = F;

event check_log()
	{
	if ( ! done && file_size("DONE") < 0 )
		system("../check-log.sh");
	if ( file_size("DONE") >= 0 )
		done = T;
	if ( done )
		{
		Cluster::publish(Cluster::worker_topic, finish);
		Cluster::publish(Cluster::proxy_topic, finish);
		}
	schedule 0.2sec { check_log() };
	}

event Cluster::node_down(name: string, id: string)
	{
	add nodes_down[name];
	if ( |nodes_down| == |Cluster::nodes| )
		terminate();
	}

event zeek_init()
	{
	schedule 0.2sec { check_log() };
	}
# @TEST-END-FILE

# @TEST-START-FILE node.zeek
@load ./common.zeek

event finish()
	{
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load ./common.zeek

# The feed has 4 IPs + 2 domains after filtering. Hold the trace until this
# worker's Intel store has all of them, whether they arrive one by one or
# as the snapshot the manager sends on node_up.
global have: set[string];

event zeek_init() &priority=100
	{
	suspend_processing();
	}

hook Intel::indicator_inserted(indicator: string, indicator_type: Intel::Type)
	{
	add have[indicator];
	if ( |have| == 6 )
		continue_processing();
	}

event finish()
	{
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE check-log.sh
#!/bin/sh
# DONE once the expected rows are in, plus a grace period so that any
# duplicate (the failure this test guards against) would also land.
LOG=offensive_agency.log
[ -f DONE ] && exit 0
[ -f "$LOG" ] || exit 0
[ -f notice.log ] || exit 0
if [ "$(grep -vc '^#' "$LOG")" -ge 13 ] && [ "$(grep -vc '^#' notice.log)" -ge 10 ]; then
	sleep 2
	echo "DONE" > DONE
fi
exit 0
# @TEST-END-FILE
