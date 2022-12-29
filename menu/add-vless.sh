#!/bin/bash

clear
domain=$(cat /usr/local/etc/xray/domain)
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
echo -e "========================================="
echo -e "            Add Vless Account            "
echo -e "========================================="
read -rp "User: " -e user
CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/config.json | wc -l)

if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
echo -e "========================================="
echo -e "            Add Vless Account            "
echo -e "========================================="
echo ""
echo "A client with the specified name was already created, please choose another name."
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
add-vless
fi
done

uuid=$(cat /proc/sys/kernel/random/uuid)
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#vless$/a\#= '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vless-grpc$/a\#= '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

vlesslink1="vless://$uuid@$domain:443?path=/vless&security=tls&encryption=none&host=$domain&type=ws&sni=$domain#$user"
vlesslink2="vless://$uuid@$domain:443?security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=$domain#$user"

systemctl restart xray
clear
echo -e "=========================================" | tee -a log-create-user.log
echo -e "              Vless Account              " | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Remarks          : ${user}" | tee -a log-create-user.log
echo -e "Domain           : ${domain}" | tee -a log-create-user.log
echo -e "Wildcard         : (bug.com).${domain}" | tee -a log-create-user.log
echo -e "Port TLS         : 443" | tee -a log-create-user.log
echo -e "Port gRPC        : 443" | tee -a log-create-user.log
echo -e "id               : ${uuid}" | tee -a log-create-user.log
echo -e "Encryption       : none" | tee -a log-create-user.log
echo -e "Network          : Websocket, gRPC" | tee -a log-create-user.log
echo -e "Path Websocket   : /vless" | tee -a log-create-user.log
echo -e "ServiceName      : vless-grpc" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link TLS       : ${vlesslink1}" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC      : ${vlesslink2}" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Expired On     : $exp" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo "" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
clear
menu
