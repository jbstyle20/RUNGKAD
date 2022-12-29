#!/bin/bash

clear
domain=$(cat /usr/local/etc/xray/domain)
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
echo -e "========================================="
echo -e "            Add Socks  Account           "
echo -e "========================================="
read -rp "Username: " -e user
CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/sockswstls.json | wc -l)
CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/sockswsnontls.json | wc -l)

if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
echo -e "========================================="
echo -e "            Add Socks  Account           "
echo -e "========================================="
echo ""
echo "A client with the specified name was already created, please choose another name."
echo ""
echo -e "========================================="
read -n 1 -s -r -p "Press any key to back on menu"
add-socks
fi
done

until [[ $pass =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
read -rp "Password: " -e pass
CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/sockswstls.json | wc -l)
CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/sockswsnontls.json | wc -l)
if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
echo -e "========================================="
echo -e "            Add Socks5 Account           "
echo -e "========================================="
echo -e ""
echo -e "A client with the specified name was already created, please choose another name."
echo -e ""
echo -e "========================================="
read -n 1 -s -r -p "Press any key to back on menu"
add-socks
clear
fi
done

read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#sockswstls$/a\#÷ '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/sockswstls.json
sed -i '/#sockswsnontls$/a\#÷ '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/sockswsnontls.json

echo -n "$user:$pass" | base64 > /tmp/log
socks_base64=$(cat /tmp/log)
sockslink1="socks://$socks_base64@$domain:443?path=/socks-ws&security=tls&host=$domain&type=ws&sni=$domain#$user"
sockslink2="socks://$socks_base64@$domain:80?path=/worryfree&security=none&host=$domain&type=ws#$user"

rm -rf /tmp/log

systemctl restart xray
clear
echo -e "=========================================" | tee -a log-create-user.log
echo -e "              Socks5 Account            " | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Username         : ${user}" | tee -a log-create-user.log
echo -e "Password         : ${pass}" | tee -a log-create-user.log
echo -e "Domain           : ${domain}" | tee -a log-create-user.log
echo -e "Wildcard         : (bug.com).${domain}" | tee -a log-create-user.log
echo -e "Port TLS         : 443" | tee -a log-create-user.log
echo -e "Port none TLS    : 80" | tee -a log-create-user.log
echo -e "Network          : Websocket" | tee -a log-create-user.log
echo -e "Path Websocket   : /socks-ws" | tee -a log-create-user.log
echo -e "Path Non TLS     : /worryfree" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link TLS       : ${sockslink1}" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link none TLS  : ${sockslink2}" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Expired On     : $exp" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo "" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
clear
menu
