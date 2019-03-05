#!/bin/bash
#
#.*Copyright (c) 2018, Fatih Celik
#.*All rights reserved.
#.*
#.*Redistribution and use in source and binary forms, with or without
#.*modification, are permitted provided that the following conditions are met:
#.*1. Redistributions of source code must retain the above copyright
#.*   notice, this list of conditions and the following disclaimer.
#.*2. Redistributions in binary form must reproduce the above copyright
#.*   notice, this list of conditions and the following disclaimer in the
#.*   documentation and/or other materials provided with the distribution.
#.*3. All advertising materials mentioning features or use of this software
#.*   must display the following acknowledgement:
#.*   This product includes software developed by the <organization>.
#.*4. Neither the name of the <organization> nor the
#.*   names of its contributors may be used to endorse or promote products
#.*   derived from this software without specific prior written permission.
#.*
#.*THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ''AS IS'' AND ANY
#.*EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#.*WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#.*DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
#.*DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#.*(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#.*LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#.*ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#.*(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#.*SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
####
# This script provides valid black list entries for iptables/ipset
# Make sure there are a tool chain which full of usable tools
# f.celik (Bntpro 2018) v 0.1:8-1mx

for tool in "wget" "curl" "tr" "head" "perl" "egrep" "grep" "wc" "date" "cut" "logger" "touch" "bc"
do
        if [ ! -x "/usr/bin/${tool}" ] && [ ! -x "/bin/${tool}" ]; then
                echo "There is no $tool, so you shall not pass"
                exit 10;
        fi
done

USAGE='
    Sorry, there must be at least two ipsets configured as list:set type
    Or, you can pass existing ipset name as an argument while invoking this script
    
    Usage: iptables-ipset-update.sh <Allow-IpSetName> <Deny-IpSetName>

    Above definition and parameter order is strict and can not be changed
'   
ParameterTypeError='
    Provided parameters is not type of list:set

    Usage: iptables-ipset-update.sh <Allow-IpSetName> <Deny-IpSetName>

    Above definition and parameter order is strict and can not be changed
'


if [ $# -ne 2 ]; then

	echo "$USAGE"
   	exit 13
      
fi

# Initialize some basic reqirements
allow="$1"; deny="$2"
declare -a sets
read -a sets <<< $( ipset list | egrep -A 1 "Name:" | grep -B 1 "list:set" | grep Name: | sed -e 's/Name: //g' | tr '\n' ' ' )
     
checkSets(){
local SetName="$1"

	for i in ${!sets[@]}
	do
		if [ "${sets[$i]}" == "$SetName" ]; then
			echo "$i"
			break
		fi
	done
}

if [ -z "$(checkSets $allow)" ] || [ -z "$(checkSets $deny)" ]; then

	echo "$ParameterTypeError"
	exit 23;

fi



_date=$( date +%F-%H.%M.%S )
tmpdir=$( head -c 220 /dev/urandom | tr -cd "0-9A-Za-z" | head -c 24 )
mkdir "/tmp/${tmpdir}"
if [ $? -ne 0 ]; then 
	echo "Looks like you do not have permission to write under /tmp"
  	exip 11
fi

tmpDir="/tmp/${tmpdir}"
links+=(https://www.binarydefense.com/banlist.txt)
links+=(https://rules.emergingthreats.net/blockrules/compromised-ips.txt)
links+=(https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
links+=(https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset)
links+=(https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset)
links+=(https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset)
links+=(https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/normshield_high_bruteforce.ipset)
links+=(https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/normshield_all_bruteforce.ipset)
links+=(https://iplists.firehol.org/files/normshield_all_attack.ipset)
links+=(https://iplists.firehol.org/files/normshield_high_suspicious.ipset)
links+=(https://iplists.firehol.org/files/normshield_all_suspicious.ipset)
links+=(https://iplists.firehol.org/files/sblam.ipset)
links+=(https://iplists.firehol.org/files/firehol_webclient.netset)
links+=(https://iplists.firehol.org/files/firehol_anonymous.netset)
links+=(https://iplists.firehol.org/files/pushing_inertia_blocklist.netset)
links+=(https://iplists.firehol.org/files/firehol_webserver.netset)
links+=(https://iplists.firehol.org/files/talosintel_ipfilter.ipset)
links+=(https://iplists.firehol.org/files/blocklist_net_ua.ipset)
links+=(https://iplists.firehol.org/files/normshield_all_spam.ipset)
links+=(https://iplists.firehol.org/files/blocklist_de.ipset)
links+=(https://iplists.firehol.org/files/bds_atif.ipset)
# Following lines are added for mail servers.
links+=(https://iplists.firehol.org/files/cleanmx_viruses.ipset)
links+=(https://iplists.firehol.org/files/normshield_all_spam.ipset)
links+=(https://iplists.firehol.org/files/bi_dovecot-pop3imap_0_1d.ipset)
links+=(https://iplists.firehol.org/files/bi_dovecot-pop3imap_0_1d.ipset)
links+=(https://iplists.firehol.org/files/bi_dovecot_2_30d.ipset)
links+=(https://iplists.firehol.org/files/bi_exim_0_1d.ipset)
links+=(https://iplists.firehol.org/files/cleanmx_phishing.ipset)

geoip="http://www.ipdeny.com/ipblocks/data/countries/tr.zone"


#####
fetchLists(){
        for url in ${!links[@]}
        do
                fileName=$( echo ${links[$url]} | awk -F "/" ' NF>0 { print $NF }')
                /usr/bin/wget -t 1 --waitretry=3 -c "${links[$url]}" -O "${tmpDir}/${fileName}"
                if [ $? -ne 0 ]; then
                        /usr/bin/curl --retry 1 --retry-delay 30 "${links[$url]}" -O "${tmpDir}/${fileName}"
                fi
        done
        perl -lne 'print if ! /^\s*(#.*)?$/' ${tmpDir}/*.txt ${tmpDir}/*.netset ${tmpDir}/*.ipset | sort -uV > "${tmpDir}/pf-badhost.txt"
	wget -c "${geoip}" -O "${tmpDir}/tr.zone"
}

splitIntoCategories(){
	local count subnet
        echo "splitting into subnet categories..."
	egrep -v "/" ${tmpDir}/pf-badhost.txt > ${tmpDir}/ipset-badhosts
	egrep "/" ${tmpDir}/pf-badhost.txt | cut -d "/" -f 2 | sort -n | uniq -c \
	| while read -r count subnet 
   	do

		if [ $subnet -gt 8 ]; then

    			egrep "\/${subnet}$" "${tmpDir}/pf-badhost.txt" > "${tmpDir}/ipset-subnet-${subnet}"
			echo "subnet $subnet file created " 
			echo "The $count number of networks will be blocked in /${subnet}"

   		fi
	done
}

loadIPSets(){

	local res
	echo "generating ip sets.... "
	lineCount=$( wc -l "${tmpDir}/ipset-badhosts" | cut -d " " -f 1 )
	## Proper way to loading ipsets is prepare the lists as a file and then invoke "ipset restore" command
	touch "${tmpDir}/restore_file"

 	if [ -e "${tmpDir}/restore_file" ]; then

		echo "create ${_date}-badhosts hash:ip hashsize 16384 maxelem $lineCount" >> "${tmpDir}/restore_file" 
		while read -r line
		do

			echo "add ${_date}-badhosts $line" >> "${tmpDir}/restore_file"

		done < "${tmpDir}/ipset-badhosts"
	    


	else

	    echo -e "Could not create ipset restore file" 
	    exit 15

	fi


	echo "... the next one"
 	maximum=$( wc -l ${tmpDir}/ipset-subnet-* | grep total | cut -d " " -f 2 )
   	echo "create ${_date}-subnets hash:net family inet maxelem $maximum" >> "${tmpDir}/restore_file"
	while read -r line
	do

		echo "add ${_date}-subnets $line" >> "${tmpDir}/restore_file"

   	done < <(cat ${tmpDir}/ipset-subnet* ) 

	### This part added for access IMAP/POP3 services from only Turkeys IP Blocks.
	### According to IP Blocks list gathered from ipdeny.com, we create a white list 
	### to allow IP addresses only for Turkey
	echo "... generating IMAP/POP allow list for Turkey"
	maximum=$( wc -l ${tmpDir}/tr.zone | cut -d " " -f 1 )
	(( maximum += 200 ))

		echo "create trSubnets-${_date} hash:net family inet hashsize 2048 maxelem $maximum" >> "${tmpDir}/restore_file"
		while read -r line
		do
			echo "add trSubnets-${_date} $line" >> "${tmpDir}/restore_file"
		done < <(cat ${tmpDir}/tr.zone)

	### DONE POP/IMAP

	# Create a list:set type ipset to feed black-list
	echo "create ${deny} list:set size 8" >> "${tmpDir}/restore_file"
	echo "add ${deny} ${_date}-subnets" >> "${tmpDir}/restore_file"
	echo "add ${deny} ${_date}-badhosts" >> "${tmpDir}/restore_file"

	# Create a list:set type ipset to feed white-list (allow list)
	echo "create ${allow} list:set size 8" >> "${tmpDir}/restore_file"
	echo "add ${allow} trSubnets-${_date} " >> "${tmpDir}/restore_file"

	/bin/rm -rf /etc/sysconfig/ipset
	cp -a "${tmpDir}/restore_file" /etc/sysconfig/ipset
	/usr/sbin/ipset restore < <( sed -n 1,$( echo "$(wc -l /etc/sysconfig/ipset | cut -d ' ' -f 1 ) - 5" | bc )p /etc/sysconfig/ipset )


	# Below lines written for real ipset config which is running on the system. 
	# We already create a new ipset backup file under /etc/sysconfig directory on upper lines. It contains all ipsets config
	# Since then, we just eliminate last 5 lines while restoring ipsets on active ipsets. 
	# 
	if [ $? -eq 0 ]; then

		echo "swapping old ipsets with newest ..."
		read -a listOfSets <<< $( ipset list "$deny" | grep -A 100 "Members:" | grep -v "Members:" )
		if [ ${#listOfSets[@]} -eq 0 ]; then

			echo "No old Black-List ip sets found" 
			ipset add $deny "${_date}-badhosts"
  			ipset add $deny "${_date}-subnets" 
  			logger -p local0.info "All Ip sets are updated, check log files for related dropped connection attempts"

		else
			echo "Adding new sets to Black List"
			ipset add "$deny" "${_date}-badhosts"
 		 	ipset add "$deny" "${_date}-subnets"

		   for setName in ${!listOfSets[@]}
 		   do

 			ipset del "$deny" "${listOfSets[$setName]}"
			ipset destroy "${listOfSets[$setName]}"

	 	   done

 
	 	fi

		read -a listOfSets <<< $( ipset list "$allow" | grep -A 100 "Members:" | grep -v "Members:" )
		if [ ${#listOfSets[@]} -eq 0 ]; then

			echo "No old White-List ip sets found"
			ipset add "$allow" "trSubnets-${_date}"

		else
			echo "Adding new sets to Allow List"
			ipset add "$allow" "trSubnets-${_date}"

		   for setName in "${!listOfSets[@]}"
		   do

			ipset del "$allow" "${listOfSets[$setName]}"
			ipset destroy "${listOfSets[$setName]}"

		   done

		fi
	else 

		echo "Could not restore ipset"
		exit 20 

	fi

	logger -p local0.info "All Ip sets are updated, check log files for related dropped connection attempts"
 
}

fetchLists
splitIntoCategories
loadIPSets

# Cleaning out
/bin/rm -rf "/tmp/${tmpdir}"
