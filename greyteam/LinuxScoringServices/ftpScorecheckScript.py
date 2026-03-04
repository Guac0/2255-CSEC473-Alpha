from ftplib import FTP

SERVER = "10.0.10.6"
USER = "scoring"
PASS = "Score123"
EXPECTED = "FTP_SERVICE_OK"

try:
    ftp = FTP(SERVER, timeout=5)
    ftp.login(USER, PASS)

    data = []
    ftp.retrlines("RETR score.txt", data.append)
    ftp.quit()

    result = "\n".join(data).strip()

    if result == EXPECTED:
        print("OK")
    else:
        print("BAD")

except:
    print("DOWN")

