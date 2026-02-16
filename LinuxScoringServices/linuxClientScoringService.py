import subprocess

HOST = "cloudsdale"      
USER = "twilight"         
CMD  = "timeout 10s libreoffice --headless --version"

try:
    r = subprocess.run(
        ["ssh", f"{USER}@{HOST}", CMD],
        capture_output=True,
        text=True,
        timeout=15
    )

    if r.returncode == 0 and r.stdout.strip():
        print("OK")
    else:
        print("BAD")

except Exception:
    print("DOWN")
