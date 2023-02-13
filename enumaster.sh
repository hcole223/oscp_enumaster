#!/bin/bash

echo "################################################################"
echo "###     ______                                 __            ###"
echo "###    / ____/___  __  ______ ___  ____ ______/ /____  _____ ###"
echo "###   / __/ / __ \/ / / / __ \`__ \/ __ \`/ ___/ __/ _ \/ ___/ ###"
echo "###  / /___/ / / / /_/ / / / / / / /_/ (__  ) /_/  __/ /     ###"
echo "### /_____/_/ /_/\__,_/_/ /_/ /_/\__,_/____/\__/\___/_/      ###"
echo "###                                                          ###"
echo "################################################################"

echo "Version 1.0"

#Login with sudo in this shell for future commands
sudo echo 

#Grab arguments
ip_address=$(echo "$1")

#Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
NC='\033[0m'

#################### Normal Functions ####################
function aggressive_nmap_scan() {
        echo "Running aggressive nmap scan on all ports..."
        echo "Command: sudo nmap -v -A -p- -T4 $ip_address"
        echo
        sudo nmap -v -A -p- -T4 $ip_address > aggressive_nmap_scan.txt 2>&1 
        echo "Aggressive Scan Results:"
        echo
        cat aggressive_nmap_scan.txt
}

function full_nmap_scan() {
        echo "Running nmap scan to get open ports..."
        echo "Command: sudo nmap -v -sS -p- -T4 $ip_address"
        echo
        sudo nmap -v -sS -p- -T4 $ip_address > full_port_scan.txt 2>&1
        echo "Nmap Results:"
        echo
        cat full_port_scan.txt
        echo
}

function full_nmap_udp_scan() {
        echo "Running nmap scan to get open UDP ports..."
        echo "Command: sudo nmap -v -sI -sS -p- -T4 $ip_address"
        echo
        sudo nmap -v -sU -sS -p- -T4 $ip_address > full_port_udp_scan.txt 2>&1
        echo "Nmap UDP Results:"
        echo
        cat full_port_udp_scan.txt
        echo
}

function search_nmap_scripts() {
        read -p "What script would you like to search for: " nmap_script_choice
        echo
        echo "Results:"
        ls /usr/share/nmap/scripts/* | grep "$nmap_script_choice"
        echo
}

function search_nmap_ftp() {
        echo "Running nmap scan with all ftp scripts..."
        echo "Command: nmap --script ftp-* -p 21 $ip_address"
        echo
        nmap --script "ftp-*" -p 21 $ip_address > ftp_nmap_results.txt 2>&1
        echo "FTP Script Results:"
        echo
        cat ftp_nmap_results.txt
        echo
}

function search_nmap_smtp() {
        echo "Running nmap scan with all smtp scripts..."
        echo "Command: nmap --script smtp-* -p 25 $ip_address"
        echo
        nmap --script "smtp-*" -p 25 $ip_address > smtp_nmap_results.txt 2>&1
        echo "SMTP Script Results:"
        echo
        cat smtp_nmap_results.txt
        echo
}

function smtp_user_enum() {
        echo "Running smtp-user-enum..."
        read -p "What User/Wordlist would you like to use: " smtp_wordlist
        echo "Command: smtp-user-enum -M VRFY -u $smtp_wordlist -t $ip_address"
        echo
        smtp-user-enum -M VRFY -u $smtp_wordlist -t $ip_address > smtp_user_enum.txt 2>&1
        echo "SMTP-USER-ENUM Results:"
        echo
        cat smtp_user_enum.txt
        echo
}

function webapp_webdav_test() {
        echo "Running davtest..."
        echo "Command: davtest -url http://$ip_address"
        echo
        davtest -url http://$ip_address > davtest.txt 2>&1
        echo "Davtest Results:"
        echo
        cat davtest.txt
        echo
}

function webapp_dirb_scan() {
        echo "Running dirbuster..."
        echo "Command: dirb http://$ip_address -f"
        echo
        dirb http://$ip_address -f > dirb_scan.txt 2>&1
        echo "Dirbuster Results:"
        echo
        cat dirb_scan.txt
        echo
}

function webapp_nikto_scan() {
        echo "Running nikto..."
        echo "Command: nikto -h $ip_address -ask no"
        echo
        nikto -h $ip_address -ask no > nikto_scan.txt 2>&1
        echo "Nikto Results:"
        echo
        cat nikto_scan.txt
        echo
}

function nmap_pop3_scan() {
        echo "Running nmap scan with all pop3 scripts..."
        echo "Command: nmap --script pop3-* -p 110,995 $ip_address"
        echo
        nmap --script "pop3-*" -p 110,995 $ip_address > pop3_nmap_results.txt 2>&1
        echo "POP3 Script Results:"
        echo
        cat pop3_nmap_results.txt
        echo
}

function find_rpc_info() {
        echo "Running rpcinfo..."
        echo "Command: rpcinfo -p $ip_address"
        echo
        rpcinfo -p $ip_address > rpcinfo_results.txt 2>&1
        echo "Rpcinfo Results:"
        echo
        cat rpcinfo_results.txt
        echo
}

function enum4linux_scan() {
        echo "Running enum4linux..."
        echo "Command: enum4linux $ip_address"
        echo
        enum4linux $ip_address > enum4linux_results.txt 2>&1
        echo "Enum4linux Results:"
        echo
        cat enum4linux_results.txt
        echo
}

function SAMRDump_Scan() {
        echo "Running SAMRDump..."
        echo "Command: impacket-samrdump [domain]/[user]:[password]@$ip_address"
        echo
        read -p "Domain: " samr_domain
        read -p "Username: " samr_user
        read -p "Password: " samr_password
        impacket-samrdump $samr_domain/$samr_user:$samr_password@$ip_address > SAMRDump_results.txt 2>&1
        echo "SAMRDump Results:"
        echo
        cat SAMRDump_results.txt
        echo
}

function smb_nmap_scan() {
        echo "Running Nmap SMB Scan..."
        echo "Command: nmap --script smb-* -p 139,445 $ip_address"
        echo
        nmap --script "smb-*" -p 139,445 $ip_address > smb_nmap_results.txt 2>&1
        echo "Nmap SMB Results:"
        echo
        cat smb_nmap_results.txt
        echo
}

function smbclient_open_scan() {
        echo "Running smbclient open scan..."
        echo "Command: smbclient -L $ip_address -U \" \"%\" \""
        echo
        smbclient -L $ip_address -U " "%" " > smbclient_open_results.txt 2>&1
        echo "Smbclient Open Results:"
        echo
        cat smbclient_open_results.txt
        echo
}

function smbclient_auth_scan() {
        echo "Running smbclient authenticated scan..."
        echo "Command: smbclient -L $ip_address -U[user]%[pass]"
        echo
        read -p "Username: " smb_user
        read -p "Password: " smb_pass
        echo
        smbclient -L $ip_address -U=$smb_user%$smb_pass > smbclient_auth_results.txt 2>&1
        echo "Smbclient Authenticated Results:"
        echo
        cat smbclient_auth_results.txt
        echo
}

function mysql_nmap_scan() {
        echo "Running Nmap MySQL Scan..."
        echo "Command: nmap --script mysql-* -p 3306 $ip_address"
        echo
        nmap --script "mysql-*" -p 3306 $ip_address > mysql_nmap_results.txt 2>&1
        echo "Nmap MySQL Results:"
        echo
        cat mysql_nmap_results.txt
        echo
}

function autorecon_scan() {
        echo "Running Autorecon Scan..."
        echo "Command: autorecon $ip_address"
        echo
        autorecon $ip_address > autorecon_results.txt 2>&1
        echo "Autorecon Results:"
        echo
        cat autorecon_results.txt
        echo
}

function query_specific_nameserver() {
        echo "Performing DNS Query on Specific Nameserver..."
        echo "Command: dig @[nameserver ip] [host/domain]"
        echo
        read -p "Nameserver: " nameserver_ip
        read -p "Host/Domain: " host_domain_lookup
        dig @$nameserver_ip $host_domain_lookup > nameserver_specific_results.txt 2>&1
        echo "Lookup Results:"
        echo
        cat nameserver_specific_results.txt
        echo
}

function query_record_nameserver() {
        echo "Performing search on specific nameserver for specific record types..."
        echo "Command: dig @[nameserver ip] [host/domain] [record type]"
        echo
        read -p "Nameserver: " namserver_ip
        read -p "Host/Domain: " host_domain_lookup
        read -p "Record Type: " record_type
        dig @$nameserver_ip $host_domain_lookup $record_type > recordtype_specific_results.txt 2>&1
        echo "$record_type Lookup  Results:"
        echo
        cat recordtype_specific_results.txt
        echo
}

function dns_reverse_lookup() {
        echo "Performing DNS reverse lookup..."
        echo "Command: dig -x [ip address]"
        echo
        read -p "IP to perofm lookup on: " ip_lookup
        dig -x $ip_lookup > reverse_lookup_results.txt 2>&1
        echo "Reverse Lookup Results:"
        echo
        cat reverse_lookup_results.txt
        echo
}

function search_all_dns_records() {
        echo "Performing DNS query for all record types..."
        echo "Command: dig @[nameserver ip] [domain/host] ANY"
        echo
        read -p "Nameserver_ip: " nameserver_ip
        read -p "Host/Domain: " host_domain_lookup
        echo
        dig @$nameserver_ip $host_domain_lookup ANY > all_recordtype_results.txt 2>&1
        echo "All Record Results:"
        echo
        cat all_recordtype_results.txt
        echo
}

function dnsrecon_scan() {
        echo "Performing dnsrecon..."
        echo "Command: dnsrecon -d [target domain] -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml"
        echo
        read -p "Domain: " domain_dnsrecon
        echo
        dnsrecon -d $domain_dnsrecon -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml 2>&1
        echo
        cat dnsrecon.xml
        echo
}

function nmblookup_scan() {
        echo "Performing nmblookup..."
        echo "Command: nmblookup -A [target ip]"
        echo
        nmblookup -A $ip_address > nmblookup_results.txt 2>&1
        echo
        cat nmblookup_results.txt
        echo
}

function snmpcheck_scan() {
        echo "Performing Snmpcheck Scan..."
        echo "Command: snmpcheck $ip_address -c public"
        echo
        snmpcheck $ip_address -c public > snmpcheck_results.txt 2>&1
        echo
        cat snmpcheck_results.txt
        echo
}

function snmpenum_scan() {
        echo "Performing Snmpenum Scan..."
        echo "Command: snmpenum $ip_address public [os].txt"
        echo
        read -p "Linux or Windows: " os_choice
        snmpenum $ip_address public $os_choice.txt > snmpenum_results.txt 2>&1
        echo
        cat snmpenum_results.txt
        echo
}

function onesixtyone_scan() {
        echo "Performing Onesixtyone Scan..."
        echo "Command: onesixtyone -c /usr/share/wordlists/dict.txt $ip_address"
        echo
        onesixtyone -c /usr/share/wordlists/dict.txt $ip_address > onesixtyone_results.txt 2>&1
        echo
        cat onesixtyone_results.txt
        echo
}

#########################################################

#################### Choice Functions ####################
function choice_nmap() {
        echo
        printf "${GREEN}--------------- Begin Nmap ---------------${NC}\n"
        echo "Nmap Scan Options:"
        echo "1. Full Port TCP Scan"
        echo "2. Aggressive All Port Scan"
        echo "3. Full Port UDP Scan"
        echo "4. Search Nmap Scripts by Keyword"
        echo
        read -p "Choice: " nmap_choice

        if [[ $nmap_choice -eq "1" ]]; then
                full_nmap_scan
        elif [[ $nmap_choice -eq "2" ]]; then
                aggressive_nmap_scan
        elif [[ $nmap_choice -eq "3" ]]; then
                full_nmap_udp_scan
        elif [[ $nmap_choice -eq "4" ]]; then
                search_nmap_scripts
        else
                echo "Invalid Option"
        fi
        echo
        printf "${RED}--------------- End Nmap ---------------${NC}\n"
}

function choice_webapp() {
        echo
        printf "${GREEN}--------------- Begin Web App ---------------${NC}\n"
        echo "Web Application Options:"
        echo "1. Nikto (Web Vulnerability Scanner)"
        echo "2. Dirbuster (Hidden Directory Scanner)"
        echo "3. Davtest (Test for potential WebDAV Exploitation)"
        echo
        read -p "Choice: " webapp_choice

        if [[ $webapp_choice -eq "1" ]]; then
                webapp_nikto_scan
        elif [[ $webapp_choice -eq "2" ]]; then
                webapp_dirb_scan
        elif [[ $webapp_choice -eq "3" ]]; then
                webapp_webdav_test
        fi
        echo
        printf "${RED}--------------- End Web App ---------------${NC}\n"
}

function choice_smb() {
        echo
        printf "${GREEN}--------------- Begin SMB/Samba ---------------${NC}\n"
        echo "SMB/Samba Options:"
        echo "1. enum4linux"
        echo "2. SAMRDump (Grabs SAMR info)"
        echo "3. NMAP SMB Scripts"
        echo "4. Smbclient Open Shares"
        echo "5. Smbclient Authenticated Shares"
        echo "6. Nmblookup"
        echo
        read -p "Choice: " smb_choice
        if [[ $smb_choice -eq "1" ]]; then
                enum4linux_scan
        elif [[ $smb_choice -eq "2" ]]; then
                SAMRDump_Scan
        elif [[ $smb_choice -eq "3" ]]; then
                smb_nmap_scan
        elif [[ $smb_choice -eq "4" ]]; then
                smbclient_open_scan
        elif [[ $smb_choice -eq "5" ]]; then
                smbclient_auth_scan
        elif [[ $smb_choice -eq "6" ]]; then
                nmblookup_scan
        fi
        echo
        printf "${RED}--------------- End SMB/Sambe ---------------${NC}\n"
}

function choice_smtp() {
        echo
        printf "${GREEN}--------------- Begin SMTP ---------------${NC}\n"
        echo "SMTP Options:"
        echo "1. Nmap SMTP Scripts"
        echo "2. SMTP-USER-ENUM"
        echo
        read -p "Choice: " smtp_choice
        if [[ $smtp_choice -eq "1" ]]; then
                search_nmap_smtp
        elif [[ $smtp_choice -eq "2" ]]; then
                smtp_user_enum
        fi
        printf "${RED}--------------- End SMTP ---------------${NC}\n"
}

function choice_ftp() {
        echo
        printf "${GREEN}--------------- Begin FTP ---------------${NC}\n"
        echo "FTP Options:"
        echo "1. Nmap FTP Scripts"
        echo
        read -p "Choice: " ftp_choice
        if [[ $ftp_choice -eq "1" ]]; then
                search_nmap_ftp
        fi
        printf "${RED}--------------- End FTP ---------------${NC}\n"
}

function choice_pop3() {
        echo
        printf "${GREEN}--------------- Begin POP3 ---------------${NC}\n"
        echo "POP3 Options:"
        echo "1. Nmap POP3 Scripts"
        echo
        read -p "Choice: " pop3_choice
        if [[ $pop3_choice -eq "1" ]]; then
                nmap_pop3_scan
        fi
        echo
        printf "${RED}--------------- End POP3 ---------------${NC}\n"
}

function choice_ssh() {
        echo 
        printf "${GREEN}--------------- Begin SSH ---------------${NC}\n"
        echo "SSH Options:"
        echo
        printf "${RED}--------------- End SSH ---------------${NC}\n"
}

function choice_rpcbind() {
        echo
        printf "${GREEN}--------------- Begin RPCBIND ---------------${NC}\n"
        echo "RPCBIND Options:"
        echo "1. Rpcinfo"
        echo
        read -p "Choice: " rpc_choice
        if [[ $rpc_choice -eq "1" ]]; then
                find_rpc_info
        fi
        echo
        printf "${RED}--------------- End RPCBIND ---------------${NC}\n"
}

function choice_snmp() {
        echo
        printf "${GREEN}--------------- Begin SNMP ---------------${NC}\n"
        echo "SNMP Options:"
        echo "1. Snmpcheck"
        echo "2. Snmpenum"
        echo "3. Onesixtyone"
        echo
        read -p "Choice: " snmp_choice
        if [[ $snmp_choice -eq "1" ]]; then
                snmpcheck_scan
        elif [[ $snmp_choice -eq "2" ]]; then
                snmpenum_scan
        elif [[ $snmp_choice -eq "3" ]]; then
                onesixtyone_scan
        fi
        echo
        printf "${RED}--------------- End SNMP ---------------${NC}\n"
}

function choice_sql() {
        echo
        printf "${GREEN}--------------- Begin SQL ---------------${NC}\n"
        echo "SQL Options:"
        echo "1. MySQL Nmap Scan"
        echo
        read -p "Choice: " sql_choice
        if [[ $sql_choice -eq "1" ]]; then
                mysql_nmap_scan
        fi
        echo
        printf "${RED}--------------- End SQL ---------------${NC}\n"
}

function choice_dns() {
        echo
        printf "${GREEN}--------------- Begin DNS ---------------${NC}\n"
        echo "DNS Options:"
        echo "1. Query Specific Nameserver"
        echo "2. Query Nameserver for Particular Record Type"
        echo "3. DNS Reverse Lookup"
        echo "4. Query Nameserver for All Records"
        echo "5. Dnsrecon"
        echo
        read -p "Choice: " dns_choice
        if [[ $dns_choice -eq "1" ]]; then
                query_specific_nameserver
        elif [[ $dns_choice -eq "2" ]]; then
                query_record_nameserver
        elif [[ $dns_choice -eq "3" ]]; then
                dns_reverse_lookup
        elif [[ $dns_choice -eq "4" ]]; then
                search_all_dns_records
        elif [[ $dns_choice -eq "5" ]]; then
                dnsrecon_scan
        fi
        echo
        printf "${RED}--------------- End DNS ---------------${NC}\n"
}

function choice_misctools() {
        echo
        printf "${GREEN}--------------- Begin Misc Tools ---------------${NC}\n"
        echo "Misc Tools Options:"
        echo "1. Autorecon"
        echo
        read -p "Choice: " misctools_choice
        if [[ $misctools_choice -eq "1" ]]; then
                autorecon_scan
        fi
        echo
        printf "${RED}--------------- End Misc Tools ---------------${NC}\n"
}

##########################################################

#Main Logic
while [[ "1" -eq "1" ]];
do
        echo
        echo "What operation would you like to perform?"
        echo "1. Nmap"
        echo "2. Web Application"
        echo "3. SMB/Samba"
        echo "4. SMTP"
        echo "5. FTP"
        echo "6. POP3"
        echo "7. SSH"
        echo "8. RPCBind"
        echo "9. SNMP"
        echo "10. SQL"
        echo "11. DNS"
        echo "12. Misc Enum Tools"
        read -p "Choice: " operation_choice

        if [[ $operation_choice -eq "1" ]]; then
                choice_nmap
        elif [[ $operation_choice -eq "2" ]]; then
                choice_webapp
        elif [[ $operation_choice -eq "3" ]]; then
                choice_smb
        elif [[ $operation_choice -eq "4" ]]; then
                choice_smtp
        elif [[ $operation_choice -eq "5" ]]; then
                choice_ftp
        elif [[ $operation_choice -eq "6" ]]; then
                choice_pop3
        elif [[ $operation_choice -eq "7" ]]; then
                choice_ssh
        elif [[ $operation_choice -eq "8" ]]; then
                choice_rpcbind
        elif [[ $operation_choice -eq "9" ]]; then
                choice_snmp
        elif [[ $operation_choice -eq "10" ]]; then
                choice_sql
        elif [[ $operation_choice -eq "11" ]]; then
                choice_dns
        elif [[ $operation_choice -eq "12" ]]; then
                choice_misctools
        fi
done
