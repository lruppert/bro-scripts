##
## This one tunes the alerts from HTTP::MD5 to remove networks we trust.
##
const md5_safenets : set[subnet] = {
	159.153.0.0/16, # EA online gaming
	129.89.61.1/24, # Condor software source
	131.215.125.1/24, # Condor software source
	128.230.11.56/32, # Akamai
	128.230.11.57/32, # Akamai
} &redef;

redef Notice::policy += {
       [$pred(n:Notice::Info) = { return n$note==HTTP::MD5 &&  (
					n$dst in md5_safenets); },
         $halt=T,
         $priority=3
       ]
};

