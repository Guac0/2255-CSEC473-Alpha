#!/usr/bin/env python3

import socket
import time

HOST="10.0.20.3"
PORT=6667
NICK="scorebot"
USER="scorebot 0 * :Score Bot"
CHANNEL="#operations"
TEST_MESSAGE ="scorecheck"

SSH_ENABLED=False  #make True for systemctl check
SSH_USER="cadence"
SSH_PASSWORD="FriendshipIsMagic0!" 

def send_recv(sock, msg, wait=1):
    sock.sendall((msg + "\r\n").encode())
    time.sleep(wait)
    data = sock.recv(4096).decode(errors='ignore')
    return data

def check_ngircd():
    violations=[]

    #Service Availability
    try:
        sock=socket.create_connection((HOST, PORT), timeout=5)
    except Exception as e:
        violations.append(f"Service not available: {e}")
        return violations

    try:
        #IRC Handshake
        response = send_recv(sock, f"NICK {NICK}")
        response += send_recv(sock, f"USER {USER}")
        if "001" not in response:
            violations.append("Handshake failed: Did not receive welcome message")
            sock.close()
            return violations

        #Channel Join
        response = send_recv(sock, f"JOIN {CHANNEL}")
        if f"JOIN :{CHANNEL}" not in response:
            violations.append(f"Channel join failed: {CHANNEL}")

        #Functional Message Check
        response=send_recv(sock, f"PRIVMSG {CHANNEL} :{TEST_MESSAGE}")
        if "ERROR" in response.upper():
            violations.append("Message send failed")

    finally:
        sock.close()


#Main
def main():
    violations = check_ngircd()
    if violations:
        print("NGIRCd scorecheck FAILED:")
        for v in violations:
            print(" -", v)
        with open("/tmp/score_ngircd.json", "w") as f:
            f.write(f'{{"violations": {len(violations)}, "details": {violations}}}')
        exit(1)
    else:
        print("NGIRCd scorecheck PASSED")
        with open("/tmp/score_ngircd.json", "w") as f:
            f.write('{"violations": 0, "details": []}')
        exit(0)

if __name__=="__main__":
    main()

