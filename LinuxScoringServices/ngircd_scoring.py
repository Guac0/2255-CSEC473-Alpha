#!/usr/bin/env python3

import socket
import time
import json

HOST ="10.0.20.3"
PORT =6667
NICK="scorebot"  
USER ="scorebot 0 * :Score Bot"
CHANNEL ="#operations"
TEST_MESSAGE ="scorecheck"
SOCKET_TIMEOUT=5
HANDSHAKE_TIMEOUT=10 

def send_line(sock, msg):
    """Send a line to the IRC server."""
    sock.sendall((msg + "\r\n").encode())

def recv_until(sock, expected_strings, timeout=SOCKET_TIMEOUT):
    """Receive data until one of the expected_strings appears or timeout."""
    sock.settimeout(timeout)
    buffer = ""
    start_time = time.time()
    while True:
        try:
            chunk = sock.recv(4096).decode(errors='ignore')
            buffer += chunk
        except socket.timeout:
            pass
        if any(s in buffer for s in expected_strings):
            return buffer
        if time.time() - start_time > timeout:
            break
    return buffer

def check_ngircd():
    violations = []

    #Service Availability
    try:
        sock = socket.create_connection((HOST, PORT), timeout=SOCKET_TIMEOUT)
    except Exception as e:
        violations.append(f"Service not available: {e}")
        return violations

    try:
        #IRC Handshake
        send_line(sock, f"NICK {NICK}")
        send_line(sock, f"USER {USER}")

        response = recv_until(sock, ["001"], timeout=HANDSHAKE_TIMEOUT)
        if "001" not in response:
            violations.append("Handshake failed: Did not receive welcome message")
            return violations

        #Channel Join
        send_line(sock, f"JOIN {CHANNEL}")
        join_response = recv_until(sock, [f"JOIN :{CHANNEL}", "ERROR"])
        if f"JOIN :{CHANNEL}" not in join_response:
            violations.append(f"Channel join failed: {CHANNEL}")

        #Functional Message Check
        send_line(sock, f"PRIVMSG {CHANNEL} :{TEST_MESSAGE}")
        msg_response = recv_until(sock, ["PRIVMSG", "ERROR"])
        if "ERROR" in msg_response.upper():
            violations.append("Message send failed")

    finally:
        sock.close()

    return violations

def main():
    violations = check_ngircd()
    result = {
        "violations": len(violations),
        "details": violations
    }
    with open("/tmp/score_ngircd.json", "w") as f:
        json.dump(result, f)

    if violations:
        print("NGIRCd scorecheck FAILED:")
        for v in violations:
            print(" -", v)
        exit(1)
    else:
        print("NGIRCd scorecheck PASSED")
        exit(0)

if __name__ == "__main__":
    main()

