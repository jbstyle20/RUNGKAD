#!/bin/bash

clear
NUMBER_OF_CLIENTS=$(grep -c -E "^#@ " "/usr/local/etc/xray/config.json")
if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
clear
echo -e "========================================="
echo -e "           Extend Vmess Account          "
echo -e "========================================="
echo ""
echo -e "  You have no existing clients!"
echo ""
echo -e "========================================="
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
fi

clear
echo -e "========================================="
echo -e "           Extend Vmess Account          "
echo -e "========================================="
echo -e " User  Expired  " 
echo -e "========================================="
grep -E "^#@ " "/usr/local/etc/xray/config.json" | cut -d ' ' -f 2-3 | column -t | sort | uniq
echo ""
echo -e "tap enter to go back"
echo -e "========================================="
read -rp "Input Username : " user
if [ -z $user ]; then
menu
else
read -p "Expired (days): " masaaktif
exp=$(grep -wE "^#@ $user" "/usr/local/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
now=$(date +%Y-%m-%d)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(( (d1 - d2) / 86400 ))
exp3=$(($exp2 + $masaaktif))
exp4=`date -d "$exp3 days" +"%Y-%m-%d"`
sed -i "/#@ $user/c\#@ $user $exp4" /usr/local/etc/xray/config.json
systemctl restart xray
clear
echo -e "========================================="
echo -e "     Vmess Account Success Extended      "
echo -e "========================================="
echo ""
echo -e " Client Name : $user"
echo -e " Expired On  : $exp4"
echo ""
echo -e "========================================="
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
clear
menu
fi
