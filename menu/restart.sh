#!/bin/bash

systemctl daemon-reload
systemctl enable xray
systemctl restart xray
systemctl restart nginx

echo -e "============restart berhasil===============" 
read -n 1 -s -r -p "Press any key to back on menu" 
clear
menu