#!/bin/bash
# usage: ./firewall.sh "22 23" "192.168.1.100 192.168.1.101"
# alt usage: ./firewall.sh "22 23" "any"

DEFAULT_PORTS="22"
DEFAULT_IPS="10.20.1.73 10.20.1.132 10.20.1.71 10.20.1.111 10.20.1.57 10.20.1.20 10.20.1.46 10.20.1.37 10.20.1.16 10.20.1.29"

TARGET_PORTS=${2:-$DEFAULT_PORTS}
TARGET_IPS=${1:-$DEFAULT_IPS}

ufw --force reset

ufw allow in on lo
ufw allow out on lo

for PORT in $TARGET_PORTS; do
    if [ "$TARGET_IPS" == "any" ]; then
        echo "allowing ANY IP on port $PORT"
        ufw allow "$PORT"/tcp
        ufw allow out "$PORT"/tcp
    else
        for IP in $TARGET_IPS; do
            echo "allowing $IP on port $PORT"
            ufw allow from "$IP" to any port "$PORT" proto tcp
            ufw allow to "$IP" port "$PORT" proto tcp
        done
    fi
done

ufw default deny incoming
ufw default deny outgoing

ufw --force enable
echo "waiting 10 seconds before rollback"
sleep 10
ufw --force reset
ufw disable