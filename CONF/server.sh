    server {
        listen 81;
        listen [::]:81;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name 127.0.0.1 localhost;

        ssl_certificate /etc/adi/adi.crt;
        ssl_certificate_key /etc/adi/adi.key;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20->
        ssl_prefer_server_ciphers on;

        location = /netzvmess {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:2001;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location = /netzvless {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:2002;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location = /netztrojan {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:2003;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /netzvmessgrpc {
            if ($request_method != "POST") {
                return 404;
            }
            client_body_buffer_size 1m;
            client_body_timeout 1h;
            client_max_body_size 0;
            grpc_read_timeout 1h;
            grpc_send_timeout 1h;
                        grpc_set_header X-Real-IP $remote_addr;
            grpc_pass grpc://127.0.0.1:2004;
        }

        location /netzvlessgrpc {
            if ($request_method != "POST") {
                return 404;
            }
            client_body_buffer_size 1m;
            client_body_timeout 1h;
            client_max_body_size 0;
            grpc_read_timeout 1h;
            grpc_send_timeout 1h;
                        grpc_set_header X-Real-IP $remote_addr;
            grpc_pass grpc://127.0.0.1:2005;
        }
        location /netztrojangrpc {
            if ($request_method != "POST") {
                return 404;
            }
            client_body_buffer_size 1m;
            client_body_timeout 1h;
            client_max_body_size 0;
            grpc_read_timeout 1h;
            grpc_send_timeout 1h;
                        grpc_set_header X-Real-IP $remote_addr;
            grpc_pass grpc://127.0.0.1:2006;
        }

        location = /netzshadowsocks {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:2007;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /netzshadowsocksgrpc {
            if ($request_method != "POST") {
                return 404;
            }
            client_body_buffer_size 1m;
            client_body_timeout 1h;
            client_max_body_size 0;
            grpc_read_timeout 1h;
            grpc_send_timeout 1h;
                        grpc_set_header X-Real-IP $remote_addr;
            grpc_pass grpc://127.0.0.1:2008;
        }

        location = /netztrojancf {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:2009;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location = /netzblakews {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:2010;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /netzblakegrpc {
            if ($request_method != "POST") {
                return 404;
            }
            client_body_buffer_size 1m;
            client_body_timeout 1h;
            client_max_body_size 0;
            grpc_read_timeout 1h;
            grpc_send_timeout 1h;
                        grpc_set_header X-Real-IP $remote_addr;
            grpc_pass grpc://127.0.0.1:2011;
        }

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        location / {
            if ($host ~* "\d+\.\d+\.\d+\.\d+") {
                return 400;
            }
            root /var/www/html;
            index index.html index.htm;
        }
}


