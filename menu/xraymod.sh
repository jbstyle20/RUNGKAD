#!/bin/bash

echo ""
echo -e "[ INFO ] Change Custom Xray-core"
# Install New Xray Core Custom Method
rm -rf /usr/local/bin/xray
cp /backup/xray.mod.backup /usr/local/bin/xray
chmod 755 /usr/local/bin/xray
systemctl restart xray
sleep 1.5
echo -e "[ INFO ] Change Custom Xray-core done"
echo ""
echo -e "Back to menu in 1 sec "
sleep 1
menu