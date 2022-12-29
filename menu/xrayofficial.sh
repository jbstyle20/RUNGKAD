#!/bin/bash

echo ""
echo -e "[ INFO ] Change Xray-core Official"
# Install Xray Core Official
rm -rf /usr/local/bin/xray
cp /backup/xray.official.backup /usr/local/bin/xray
chmod 755 /usr/local/bin/xray
systemctl restart xray
sleep 1.5
echo -e "[ INFO ] Change Xray-core Official done"
echo ""
echo -e "Back to menu in 1 sec "
sleep 1
menu