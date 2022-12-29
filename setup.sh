#!/bin/bash

# Check Register IP
MYIP=$(wget -qO- ipinfo.io/ip);
echo "Checking VPS"
IZIN=$( curl https://raw.githubusercontent.com/ariefrahman10/DAFTAR-IP/main/register.txt | grep "$MYIP" )
if [ "$MYIP" = "$IZIN" ]; then
echo -e "${NC}${GREEN}Permission Accepted...${NC}"
else
echo -e "${NC}${RED}DITOLAK MENTAH MENTAH WKWKWKWKKW!${NC}";
echo -e "${NC}${LIGHT}MALLLLLLLLLLLLLIIIIIIIIIIIIGGGGGGGGGGGGGGGG!!"
exit 0
fi
clear

# Getting
rm -rf xray
rm -rf install
clear

secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}
start=$(date +%s)
apt install socat netfilter-persistent fail2ban -y
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
mkdir /backup
# Install Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
cp /usr/local/bin/xray /backup/xray.official.backup
clear

# Download New Xray
cd /backup
wget -O xray.mod.backup "https://github.com/dharak36/Xray-core/releases/download/v1.0.0/xray.linux.64bit"
cd
clear

# Install Nginx
apt install nginx -y
rm /var/www/html/*.html
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
systemctl restart xray

# Input Domain
clear
echo "Input Domain"
echo " "
read -rp "Input domain kamu : " -e dns
if [ -z $dns ]; then
echo -e "Nothing input for domain!"
else
echo "$dns" > /usr/local/etc/xray/domain
fi

# Install Cert
systemctl stop nginx
domain=$(cat /usr/local/etc/xray/domain)
curl https://get.acme.sh | sh
source ~/.bashrc
cd .acme.sh
bash acme.sh --issue -d $domain --server letsencrypt --keylength ec-256 --fullchain-file /usr/local/etc/xray/xray.crt --key-file /usr/local/etc/xray/xray.key --standalone --force

# Setting
uuid=$(cat /proc/sys/kernel/random/uuid)
# xray config
cat > /etc/xray/config.json << END
{
  "log" : {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
      {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
   {
     "listen": "127.0.0.1",
     "port": "14016",
     "protocol": "vless",
      "settings": {
          "decryption":"none",
            "clients": [
               {
                 "id": "${uuid}"                 
#vless
             }
          ]
       },
       "streamSettings":{
         "network": "ws",
            "wsSettings": {
                "path": "/vless"
          }
        }
     },
     {
     "listen": "127.0.0.1",
     "port": "23456",
     "protocol": "vmess",
      "settings": {
            "clients": [
               {
                 "id": "${uuid}",
                 "alterId": 0
#vmess
             }
          ]
       },
       "streamSettings":{
         "network": "ws",
            "wsSettings": {
                "path": "/vmess"
          }
        }
     },
    {
      "listen": "127.0.0.1",
      "port": "25432",
      "protocol": "trojan",
      "settings": {
          "decryption":"none",    
           "clients": [
              {
                 "password": "${uuid}"
#trojanws
              }
          ],
         "udp": true
       },
       "streamSettings":{
           "network": "ws",
           "wsSettings": {
               "path": "/trojan-ws"
            }
         }
     },
     {
        "listen": "127.0.0.1",
     "port": "24456",
        "protocol": "vless",
        "settings": {
         "decryption":"none",
           "clients": [
             {
               "id": "${uuid}"
#vlessgrpc
             }
          ]
       },
          "streamSettings":{
             "network": "grpc",
             "grpcSettings": {
                "serviceName": "vless-grpc"
           }
        }
     },
     {
      "listen": "127.0.0.1",
     "port": "31234",
     "protocol": "vmess",
      "settings": {
            "clients": [
               {
                 "id": "${uuid}",
                 "alterId": 0
#vmessgrpc
             }
          ]
       },
       "streamSettings":{
         "network": "grpc",
            "grpcSettings": {
                "serviceName": "vmess-grpc"
          }
        }
     },
     {
        "listen": "127.0.0.1",
     "port": "33456",
        "protocol": "trojan",
        "settings": {
          "decryption":"none",
             "clients": [
               {
                 "password": "${uuid}"
#trojangrpc
               }
           ]
        },
         "streamSettings":{
         "network": "grpc",
           "grpcSettings": {
               "serviceName": "trojan-grpc"
         }
      }
   }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END

cat > /etc/xray/sockswstls.json << END
{
    "dns": {
        "hosts": {
            "domain:googleapis.cn": "googleapis.com"
        },
        "servers": [
            "8.8.4.4"
        ],
        "tag": "dns"
    },
    "inbounds": [],
    "log": {
        "loglevel": "warning"
    },
    "outbounds": [
        {
            "mux": {
                "concurrency": 8,
                "enabled": true
            },
            "protocol": "socks",
            "settings": {
                "servers": [
                    {
                        "address": "alamathost",
                        "port": 443,
                        "users": [
                            {
                                "level": 8,
                                "pass": "akun",
                                "user": "akun"
#sockswstls
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "allowInsecure": true,
                    "serverName": "alamathost"
                },
                "wsSettings": {
                    "headers": {
                        "Host": "alamathost"
                    },
                    "path": "/socks-ws"
                }
            },
            "tag": "proxy"
        },
        {
            "protocol": "freedom",
            "settings": {},
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "settings": {
                "response": {
                    "type": "http"
                }
            },
            "tag": "block"
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "inboundTag": [
                    "proxy"
                ],
                "outboundTag": "dns",
                "type": "field"
            },
            {
                "inboundTag": [
                    "http"
                ],
                "outboundTag": "proxy",
                "type": "field"
            }
        ]
    }
}
END

cat > /etc/xray/sockswsnontls.json << END
{
    "dns": {
        "hosts": {
            "domain:googleapis.cn": "googleapis.com"
        },
        "servers": [
            "8.8.4.4"
        ],
        "tag": "dns"
    },
    "inbounds": [],
    "log": {
        "loglevel": "warning"
    },
    "outbounds": [
        {
            "mux": {
                "concurrency": 8,
                "enabled": true
            },
            "protocol": "socks",
            "settings": {
                "servers": [
                    {
                        "address": "alamathost",
                        "port": 80,
                        "users": [
                            {
                                "level": 8,
                                "pass": "akun",
                                "user": "akun"
#sockswsnontls
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "tlsSettings": {
                    "allowInsecure": false,
                    "serverName": "alamathost"
                },
                "wsSettings": {
                    "headers": {
                        "Host": "alamathost"
                    },
                    "path": "/worryfree"
                }
            },
            "tag": "proxy"
        },
        {
            "protocol": "freedom",
            "settings": {},
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "settings": {
                "response": {
                    "type": "http"
                }
            },
            "tag": "block"
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "inboundTag": [
                    "proxy"
                ],
                "outboundTag": "dns",
                "type": "field"
            },
            {
                "inboundTag": [
                    "http"
                ],
                "outboundTag": "proxy",
                "type": "field"
            }
        ]
    }
}
END


# Set Nginx Conf
cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes 1;
pid /var/run/nginx.pid;
events {
    multi_accept on;
    worker_connections 1024;
}
http {
    gzip on;
    gzip_vary on;
    gzip_comp_level 5;
    gzip_types text/plain application/x-javascript text/xml text/css;
    autoindex on;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    client_max_body_size 32M;
    client_header_buffer_size 8m;
    large_client_header_buffers 8 8m;
    fastcgi_buffer_size 8m;
    fastcgi_buffers 8 8m;
    fastcgi_read_timeout 600;
    set_real_ip_from 23.235.32.0/20;
    set_real_ip_from 43.249.72.0/22;
    set_real_ip_from 103.244.50.0/24;
    set_real_ip_from 103.245.222.0/23;
    set_real_ip_from 103.245.224.0/24;
    set_real_ip_from 104.156.80.0/20;
    set_real_ip_from 140.248.64.0/18;
    set_real_ip_from 140.248.128.0/17;
    set_real_ip_from 146.75.0.0/17;
    set_real_ip_from 151.101.0.0/16;
    set_real_ip_from 157.52.64.0/18;
    set_real_ip_from 167.82.0.0/17;
    set_real_ip_from 167.82.128.0/20;
    set_real_ip_from 167.82.160.0/20;
    set_real_ip_from 167.82.224.0/20;
    set_real_ip_from 172.111.64.0/18;
    set_real_ip_from 185.31.16.0/22;
    set_real_ip_from 199.27.72.0/21;
    set_real_ip_from 199.232.0.0/16;
    set_real_ip_from 2a04:4e40::/32;
    set_real_ip_from 2a04:4e42::/32;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;
    set_real_ip_from 120.52.22.96/27;
    set_real_ip_from 205.251.249.0/24;
    set_real_ip_from 180.163.57.128/26;
    set_real_ip_from 204.246.168.0/22;
    set_real_ip_from 18.160.0.0/15;
    set_real_ip_from 205.251.252.0/23;
    set_real_ip_from 54.192.0.0/16;
    set_real_ip_from 204.246.173.0/24;
    set_real_ip_from 54.230.200.0/21;
    set_real_ip_from 120.253.240.192/26;
    set_real_ip_from 116.129.226.128/26;
    set_real_ip_from 130.176.0.0/17;
    set_real_ip_from 108.156.0.0/14;
    set_real_ip_from 99.86.0.0/16;
    set_real_ip_from 205.251.200.0/21;
    set_real_ip_from 223.71.71.128/25;
    set_real_ip_from 13.32.0.0/15;
    set_real_ip_from 120.253.245.128/26;
    set_real_ip_from 13.224.0.0/14;
    set_real_ip_from 70.132.0.0/18;
    set_real_ip_from 15.158.0.0/16;
    set_real_ip_from 13.249.0.0/16;
    set_real_ip_from 18.238.0.0/15;
    set_real_ip_from 18.244.0.0/15;
    set_real_ip_from 205.251.208.0/20;
    set_real_ip_from 65.9.128.0/18;
    set_real_ip_from 130.176.128.0/18;
    set_real_ip_from 58.254.138.0/25;
    set_real_ip_from 54.230.208.0/20;
    set_real_ip_from 116.129.226.0/25;
    set_real_ip_from 52.222.128.0/17;
    set_real_ip_from 18.164.0.0/15;
    set_real_ip_from 64.252.128.0/18;
    set_real_ip_from 205.251.254.0/24;
    set_real_ip_from 54.230.224.0/19;
    set_real_ip_from 71.152.0.0/17;
    set_real_ip_from 216.137.32.0/19;
    set_real_ip_from 204.246.172.0/24;
    set_real_ip_from 18.172.0.0/15;
    set_real_ip_from 120.52.39.128/27;
    set_real_ip_from 118.193.97.64/26;
    set_real_ip_from 223.71.71.96/27;
    set_real_ip_from 18.154.0.0/15;
    set_real_ip_from 54.240.128.0/18;
    set_real_ip_from 205.251.250.0/23;
    set_real_ip_from 180.163.57.0/25;
    set_real_ip_from 52.46.0.0/18;
    set_real_ip_from 223.71.11.0/27;
    set_real_ip_from 52.82.128.0/19;
    set_real_ip_from 54.230.0.0/17;
    set_real_ip_from 54.230.128.0/18;
    set_real_ip_from 54.239.128.0/18;
    set_real_ip_from 130.176.224.0/20;
    set_real_ip_from 36.103.232.128/26;
    set_real_ip_from 52.84.0.0/15;
    set_real_ip_from 143.204.0.0/16;
    set_real_ip_from 144.220.0.0/16;
    set_real_ip_from 120.52.153.192/26;
    set_real_ip_from 119.147.182.0/25;
    set_real_ip_from 120.232.236.0/25;
    set_real_ip_from 54.182.0.0/16;
    set_real_ip_from 58.254.138.128/26;
    set_real_ip_from 120.253.245.192/27;
    set_real_ip_from 54.239.192.0/19;
    set_real_ip_from 18.68.0.0/16;
    set_real_ip_from 18.64.0.0/14;
    set_real_ip_from 120.52.12.64/26;
    set_real_ip_from 99.84.0.0/16;
    set_real_ip_from 130.176.192.0/19;
    set_real_ip_from 52.124.128.0/17;
    set_real_ip_from 204.246.164.0/22;
    set_real_ip_from 13.35.0.0/16;
    set_real_ip_from 204.246.174.0/23;
    set_real_ip_from 36.103.232.0/25;
    set_real_ip_from 119.147.182.128/26;
    set_real_ip_from 118.193.97.128/25;
    set_real_ip_from 120.232.236.128/26;
    set_real_ip_from 204.246.176.0/20;
    set_real_ip_from 65.8.0.0/16;
    set_real_ip_from 65.9.0.0/17;
    set_real_ip_from 108.138.0.0/15;
    set_real_ip_from 120.253.241.160/27;
    set_real_ip_from 64.252.64.0/18;
    set_real_ip_from 13.113.196.64/26;
    set_real_ip_from 13.113.203.0/24;
    set_real_ip_from 52.199.127.192/26;
    set_real_ip_from 13.124.199.0/24;
    set_real_ip_from 3.35.130.128/25;
    set_real_ip_from 52.78.247.128/26;
    set_real_ip_from 13.233.177.192/26;
    set_real_ip_from 15.207.13.128/25;
    set_real_ip_from 15.207.213.128/25;
    set_real_ip_from 52.66.194.128/26;
    set_real_ip_from 13.228.69.0/24;
    set_real_ip_from 52.220.191.0/26;
    set_real_ip_from 13.210.67.128/26;
    set_real_ip_from 13.54.63.128/26;
    set_real_ip_from 99.79.169.0/24;
    set_real_ip_from 18.192.142.0/23;
    set_real_ip_from 35.158.136.0/24;
    set_real_ip_from 52.57.254.0/24;
    set_real_ip_from 13.48.32.0/24;
    set_real_ip_from 18.200.212.0/23;
    set_real_ip_from 52.212.248.0/26;
    set_real_ip_from 3.10.17.128/25;
    set_real_ip_from 3.11.53.0/24;
    set_real_ip_from 52.56.127.0/25;
    set_real_ip_from 15.188.184.0/24;
    set_real_ip_from 52.47.139.0/24;
    set_real_ip_from 18.229.220.192/26;
    set_real_ip_from 54.233.255.128/26;
    set_real_ip_from 3.231.2.0/25;
    set_real_ip_from 3.234.232.224/27;
    set_real_ip_from 3.236.169.192/26;
    set_real_ip_from 3.236.48.0/23;
    set_real_ip_from 34.195.252.0/24;
    set_real_ip_from 34.226.14.0/24;
    set_real_ip_from 13.59.250.0/26;
    set_real_ip_from 18.216.170.128/25;
    set_real_ip_from 3.128.93.0/24;
    set_real_ip_from 3.134.215.0/24;
    set_real_ip_from 52.15.127.128/26;
    set_real_ip_from 3.101.158.0/23;
    set_real_ip_from 52.52.191.128/26;
    set_real_ip_from 34.216.51.0/25;
    set_real_ip_from 34.223.12.224/27;
    set_real_ip_from 34.223.80.192/26;
    set_real_ip_from 35.162.63.192/26;
    set_real_ip_from 35.167.191.128/26;
    set_real_ip_from 44.227.178.0/24;
    set_real_ip_from 44.234.108.128/25;
    set_real_ip_from 44.234.90.252/30;
    set_real_ip_from 204.93.240.0/24;
    set_real_ip_from 204.93.177.0/24;
    set_real_ip_from 199.27.128.0/21;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    real_ip_header CF-Connecting-IP;
    include /etc/nginx/conf.d/*.conf;
}
EOF

# Set Xray Nginx Conf
cat > /etc/nginx/conf.d/xray.conf << EOF
    server {
             listen 81;
             listen [::]:81;
             root /var/www/html;
        }
    server {
             listen 80;
             listen [::]:80;
             listen 443 ssl http2 reuseport;
             listen [::]:443 http2 reuseport; 
             server_name *.$domain;
             ssl_certificate /usr/local/etc/xray/xray.crt;
             ssl_certificate_key /usr/local/etc/xray/xray.key;
             ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
             ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
        }
EOF

sed -i '$ ilocation = /vless' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_pass http://127.0.0.1:14016;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation = /vmess' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_pass http://127.0.0.1:23456;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation = /trojan-ws' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_pass http://127.0.0.1:25432;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation = /socks-ws' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_pass http://127.0.0.1:25432;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation ^~ /vless-grpc' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_pass grpc://127.0.0.1:24456;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation ^~ /vmess-grpc' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_pass grpc://127.0.0.1:31234;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation ^~ /trojan-grpc' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_pass grpc://127.0.0.1:33456;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

service nginx restart
service xray restart

echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sed -i '/fs.file-max/d' /etc/sysctl.conf
sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo "fs.file-max = 1000000
fs.inotify.max_user_instances = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
# forward ipv4
net.ipv4.ip_forward = 1">>/etc/sysctl.conf

iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

cd /usr/bin
# Download Main Menu
wget -O menu "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/menu.sh"
wget -O m-vmess "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/m-vmess.sh"
wget -O m-vless "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/m-vless.sh"
wget -O m-trojan "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/m-trojan.sh"
wget -O m-socks "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/m-socks.sh"
wget -O all-xray "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/all-xray.sh"
wget -O xraymod "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/xraymod.sh"
wget -O xrayofficial "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/xrayofficial.sh"
wget -O kernel-bbr "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/kernel-bbr.sh"
wget -O kernel-xanmod "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/kernel-xanmod.sh"
wget -O restart "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/restart.sh"
wget -O ganti-domain "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/ganti-domain.sh"
chmod +x menu
chmod +x m-vmess
chmod +x m-vless
chmod +x m-trojan
chmod +x m-socks
chmod +x all-xray
chmod +x xraymod
chmod +x xrayofficial
chmod +x kernel-bbr
chmod +x kernel-xanmod
chmod +x restart
chmod +x ganti-domain

# Vmess
wget -O add-vmess "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/add-vmess.sh"
wget -O del-vmess "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/del-vmess.sh"
wget -O extend-vmess "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/extend-vmess.sh"
chmod +x add-vmess
chmod +x del-vmess
chmod +x extend-vmess

# Vless
wget -O add-vless "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/add-vless.sh"
wget -O del-vless "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/del-vless.sh"
wget -O extend-vless "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/extend-vless.sh"
chmod +x add-vless
chmod +x del-vless
chmod +x extend-vless

# Trojan
wget -O add-trojan "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/add-trojan.sh"
wget -O del-trojan "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/del-trojan.sh"
wget -O extend-trojan "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/extend-trojan.sh"
chmod +x add-trojan
chmod +x del-trojan
chmod +x extend-trojan

# Socks
wget -O add-sock "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/add-socks.sh"
wget -O del-sock "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/del-socks.sh"
wget -O extend-sock "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/extend-socks.sh"
chmod +x add-socks
chmod +x del-socks
chmod +x extend-socks

# All
wget -O add-all "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/add-all.sh"
wget -O del-all "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/del-all.sh"
wget -O extend-all "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD/main/menu/extend-all.sh"
chmod +x add-all
chmod +x del-all
chmod +x extend-all
cd

clear
echo "==========================================================" | tee -a log-install.log
echo "" | tee -a log-install.log
echo "   >>> Service & Port" | tee -a log-install.log
echo "   - Vmess Websocket             : 443" | tee -a log-install.log
echo "   - Vless Websocket             : 443" | tee -a log-install.log
echo "   - Trojan Websocket            : 443" | tee -a log-install.log
echo "   - Socks Websocket             : 443" | tee -a log-install.log
echo "   - Vmess gRPC                  : 443" | tee -a log-install.log
echo "   - Vless gRPC                  : 443" | tee -a log-install.log
echo "   - Trojan gRPC                 : 443" | tee -a log-install.log
echo "   - Socks Websocket non tls     : 80"  | tee -a log-install.log
echo "" | tee -a log-install.log
echo "==========================================================" | tee -a log-install.log
echo ""
echo ""
rm -f install
secs_to_human "$(($(date +%s) - ${start}))"
echo -ne "[ WARNING ] reboot now ? (Y/N) "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi
