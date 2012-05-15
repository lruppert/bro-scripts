#
# This aims to handle DNS alerts from a variety of sources.
#
# Written by Lou Ruppert
# Syracuse University
#
module DNS;

export {
	type malware_domain: record {
    		category: string &optional; # eg "Zeus C2", "Flashback", etc
    		severity: string &optional; # low, medium, high
		confidence: string &optional; # Good for cif dumps
		description: string &optional; # Anything for the IDS
		raw: string &optional; # Raw record, in case it holds more data
		source: string; # Where did we get it?
	};
	const hostile_domain_list: table[string] of malware_domain &redef;
	const okay_to_lookup_hostile_domains: set[addr] &redef;
}

#redef hostile_domain_list += { 
#	["zeustracker.abuse.ch"] = [$source="test", $confidence="high", $description="Awesome"],
#	["tuk-tuk.com"] = [$source="Zeus", $category="Zeus", $description = "Zeus C2 node"],
#};
#
#redef DNS::okay_to_lookup_hostile_domains = { 192.168.1.1, 10.2.1.1,};
#

redef enum Notice::Type += {
	Sensitive_Domain
};

#
# Simple helper function stolen from bro 1.5 code
function second_level_domain(name: string): string
        {
        local split_on_dots = split(name, /\./);
        local num_dots = length(split_on_dots);

        if ( num_dots <= 1 )
                return name;

        return fmt("%s.%s", split_on_dots[num_dots-1], split_on_dots[num_dots]);
        }

#
# DGA routines here
#
# Based on ET CURRENT_EVENTS 1:2014363
function zeus_dga(name: string): bool
        {
        local split_on_dots = split(name, /\./);
        local num_dots = length(split_on_dots);

        if ( num_dots <= 1 )
                return F;
        if ( byte_len(split_on_dots[num_dots-1]) >= 33 && split_on_dots[num_dots
] == "ru" ) {

                return T;
        }
        return F;
}



event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=0
	{
	# Don't alert on DNS servers looking things up.  It's pointless.
	if (c$id$orig_h !in okay_to_lookup_hostile_domains) {
		local message: string;
	# Check for DGA-looking domains
		if (zeus_dga(query))
                        message=fmt("Possible Zeus DGA %s",query);
                        NOTICE([$note=Sensitive_Domain,
                                $msg=message,
                                $conn=c]);

	# Check for blacklisted domains
		local sld = second_level_domain(query);
		if (sld in hostile_domain_list)
			message=fmt("Malware domain %s",query);
			if (hostile_domain_list[sld]?$category) {
				message=fmt("%s DNS domain %s",hostile_domain_list[sld]$category,query);
			}
			NOTICE([$note=Sensitive_Domain,
				$msg=message,
				$conn=c]);
	
	}
	}
