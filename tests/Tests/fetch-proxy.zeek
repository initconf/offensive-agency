# @TEST-DOC: fetch_proxy routes the download through an HTTP proxy. The feed host does not resolve, so only the proxy path can succeed.
#
# @TEST-EXEC: btest-bg-run proxy "python3 ../proxy.py $TEST_FILES/feed.ndjson"
# @TEST-EXEC: for i in $(seq 50); do test -s proxy/proxy.zeek && break; sleep 0.1; done
# @TEST-EXEC: btest-bg-run zeek "zeek $PACKAGE/__load__.zeek ../proxy/proxy.zeek ../test.zeek"
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/.stdout
# @TEST-EXEC: grep -q 'GET http://feed.offensive-agency.invalid/hosts.ndjson' proxy/requests.txt

@TEST-START-FILE proxy.py
# Minimal forward proxy: answers every absolute-URI GET with the given file.
import http.server, sys

body = open(sys.argv[1], "rb").read()

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open("requests.txt", "a") as f:
            f.write(f"GET {self.path}\n")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", '"t1"')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

srv = http.server.HTTPServer(("127.0.0.1", 0), H)
with open("proxy.zeek.tmp", "w") as f:
    f.write(f'redef OffensiveAgency::fetch_proxy = "http://127.0.0.1:{srv.server_port}";\n')
import os
os.rename("proxy.zeek.tmp", "proxy.zeek")
srv.timeout = 30
srv.handle_request()
@TEST-END-FILE

@TEST-START-FILE test.zeek
redef exit_only_after_terminate = T;
redef OffensiveAgency::feed_url = "http://feed.offensive-agency.invalid/hosts.ndjson";
redef OffensiveAgency::state_dir = "state";

event OffensiveAgency::feed_updated(n_ips: count, n_domains: count)
	{
	print fmt("feed via proxy: ips=%d domains=%d", n_ips, n_domains);
	terminate();
	}
@TEST-END-FILE
