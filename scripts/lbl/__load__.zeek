##! offensive-agency: LBL site add-on.
##!
##! NOT loaded by the package's default __load__. LBL loads it explicitly,
##! after the package:
##!
##!     @load offensive-agency
##!     @load offensive-agency/lbl
##!
##! It does two things:
##!   1. Defines the options a site config file sets (scanner allowlist,
##!      never-drop nets, drop switch). The package does NOT register any
##!      config file: it ships only lbl.cfg.example (placeholder values).
##!      The real site file lives outside the repo and is registered in
##!      local.zeek with
##!          redef Config::config_files += { "/path/to/lbl.cfg" };
##!      Never set the same option in two config files: the Config
##!      framework does not order files.
##!   2. Loads notice-policy.zeek: every finding goes to notice.log
##!      (ACTION_LOG), the ones that need a human today are also emailed,
##!      and, while lbl_drop_inbound is T, external inbound agent hosts get
##!      ACTION_DROP, executed by the site's drop machinery (e.g.
##!      NetControl). No ACTION_ALARM: nothing goes to notice_alarm.log.

@load policy/frameworks/notice/actions/drop
@load ../main

module OffensiveAgency;

export {
	## Add ACTION_DROP to inbound findings from external agent hosts.
	## Off by default; enable it from the site config file.
	option lbl_drop_inbound = F;

	## Never drop these, even when lbl_drop_inbound is on.
	option lbl_never_drop_nets: set[subnet] = {};

	## Notice types that are emailed (in addition to notice.log).
	option lbl_email_types: set[Notice::Type] = {
		OffensiveAgency::Agent_Implant_Or_Webshell,
		OffensiveAgency::Local_Host_Listed,
		OffensiveAgency::Agent_Running_Locally,
		OffensiveAgency::Outbound_To_Agent_Host,
		OffensiveAgency::Agent_Domain_Contact,
		OffensiveAgency::OAST_Callback_Lookup,
		OffensiveAgency::Feed_Problem,
	};
}

@load ./notice-policy
