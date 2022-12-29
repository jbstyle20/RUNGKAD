#!/bin/bash

clear
domain=$(cat /usr/local/etc/xray/domain)
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${user_EXISTS} == '0' ]]; do
echo -e "========================================="
echo -e "            Add Trojan Account           "
echo -e "========================================="
read -rp "User: " -e user
user_EXISTS=$(grep -w $user /usr/local/etc/xray/config.json | wc -l)

if [[ ${user_EXISTS} == '1' ]]; then
clear
echo -e "========================================="
echo -e "            Add Trojan Account           "
echo -e "========================================="
echo ""
echo "A client with the specified name was already created, please choose another name."
echo ""
echo -e "========================================="
read -n 1 -s -r -p "Press any key to back on menu"
add-trojan
fi
done

uuid=$(cat /proc/sys/kernel/random/uuid)
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#trojanws$/a\#& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#trojan-grpc$/a\#& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

trojanlink1="trojan://$uuid@$domain:443?path=/trojan-ws&security=tls&host=$domain&type=ws&sni=$domain#$user"
trojanlink2="trojan://${uuid}@$domain:443?security=tls&encryption=none&type=grpc&serviceName=trojan-grpc&sni=$domain#$user"

systemctl restart xray
clear
echo -e "=========================================" | tee -a log-create-user.log
echo -e "             Trojan Account             " | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Remarks          : ${user}" | tee -a log-create-user.log
echo -e "Host/IP          : ${domain}" | tee -a log-create-user.log
echo -e "Wildcard         : (bug.com).${domain}" | tee -a log-create-user.log
echo -e "Port TLS         : 443" | tee -a log-create-user.log
echo -e "Port gRPC        : 443" | tee -a log-create-user.log
echo -e "Password         : ${uuid}" | tee -a log-create-user.log
echo -e "Network          : Websocket, gRPC" | tee -a log-create-user.log
echo -e "Path Websocket   : /trojan-ws" | tee -a log-create-user.log
echo -e "ServiceName      : trojan-grpc" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link TLS       : ${trojanlink1}" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC      : ${trojanlink2}" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Expired On     : $exp" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo "" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
clear
menu
