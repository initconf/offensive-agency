##! offensive-agency: detect offensive AI agent infrastructure and activity.
##!
##! Pulls the offensive.agency feed (https://www.offensive.agency/api, data by
##! ONYPHE) on the manager, syncs its IPs and domains into the Intel framework,
##! and adds behavioural signatures of the tracked agents. See README.rst.
##!
##! Configuration is done with Config framework options; copy
##! offensive-agency.cfg.example, edit it, and add it to Config::config_files.
##! Set Site::local_nets: direction (inbound/outbound/local) drives every
##! notice decision.

@load ./main
@load ./feed
@load ./threatdefence
@load ./intel-match
@load ./traces
