# iptables-ipset-update
An iptables blacklist manager for IP addresses marked as harmful

Please provide two ipset names as an argument while invoking this script. Those ipset names must be "list:set" type. This version specially prepared for MX servers and aims to stop IP addresses which have bad reputition. Also restricts to access for well-known MX ports such as POP3(s)/IMAP(s). Restrictions basically covers only countries IP addresses blocks like "Turkey"

Usage: iptables-ipset-update.sh  ALLOW  DENY<br>
First parameter (ALLOW) is defines your white list ipset and basically just selects countries IP addresses blocks. If you decide to change it then you may change it directly in script. In this script, please change the value of "geoip" variable for change your country IP Blocks.<br>
The second parameter (DENY) is for to define ipset name used as blocking purposes. A crontab line can be handy to update that ipset list within specific time periods with help of this script.
