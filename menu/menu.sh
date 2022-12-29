#!/bin/bash

xray_service=$(systemctl status xray | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
nginx_service=$(systemctl status nginx | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
# STATUS SERVICE XRAY 
if [[ $xray_service == "running" ]]; then 
   status_xray="[ ON ] Running"
else
   status_xray="[ OFF ] Not Running"
fi
# STATUS SERVICE NGINX 
if [[ $nginx_service == "running" ]]; then 
   status_nginx="[ ON ] Running"
else
   status_nginx="[ OFF ] Not Running"
fi

domain=$(cat /usr/local/etc/xray/domain)
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10)
CITY=$(curl -s ipinfo.io/city)
WKT=$(curl -s ipinfo.io/timezone)
DATE=$(date -R | cut -d " " -f -4)
MYIP=$(curl -sS ipv4.icanhazip.com)
clear 
echo "========================================="
echo "           [ • RUNGKAD SCRIPT • ]           "
echo "========================================="
echo " Operating System  : "`hostnamectl | grep "Operating System" | cut -d ' ' -f5-`
echo " IP Address        : $MYIP"	
echo " Service Provider  : $ISP"
echo " Timezone          : $WKT"
echo " City              : $CITY"
echo " Domain            : $domain"	
echo " Date              : $DATE"	
echo "========================================="
echo "  NGINX STATUS : $status_nginx"
echo "  XRAY STATUS  : $status_xray"
echo "========================================="
echo "           [ • RUNGKAD SCRIPT • ]           "
echo "========================================="
echo " [  1 ] Vmess Menu"
echo " [  2 ] Vless Menu"
echo " [  3 ] Trojan Menu"
echo " [  4 ] Sock Menu"
echo " [  5 ] Change Custom Xray-core"
echo " [  6 ] Change Xray-core Official"
echo " [  7 ] Update kernel + TCP BBR"
echo " [  8 ] Custom kernel XanMod"
echo " [  9 ] Restart All Service"
echo " [ 10 ] Change Domain"
echo ""
echo " Press X or [ Ctrl + C ] To Exit Script"
echo ""
echo "========================================="
echo ""
read -p " Select Menu :  "  opt
echo ""
case $opt in
1) clear ; m-vmess ;;
2) clear ; m-vless ;;
3) clear ; m-trojan ;;
4) clear ; m-socks ;;
5) clear ; xraymod ;;
6) clear ; xrayofficial ;;
7) clear ; kernel-bbr ;;
8) clear ; kernel-xanmod ;;
9) clear ; restart ;;
10) clear ; ganti-domain ;;
x) exit ;;
*) echo "Anda salah input" ; sleep 0.5 ; menu ;;
esac
