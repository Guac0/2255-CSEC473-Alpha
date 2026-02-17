import subprocess

HOSTS = ["10.0.30.4", "10.0.30.5", "10.0.30.6"] # cloudsdale", "vanhoover", "whinnyapolis"
USER  = "twilight"
CMD   = "timeout 10s libreoffice --headless --version"

any_workstation_failed  = False

for host in HOSTS:
    try:
        ssh_command_result  = subprocess.run(
            ["ssh", f"{USER}@{host}", CMD],
            capture_output=True,
            text=True,
            timeout=15
        )

        
        combined_output  = (ssh_command_result.stdout + ssh_command_result.stderr).strip()
        if ssh_command_result.returncode != 0 or "LibreOffice" not in combined_output:
            any_workstation_failed  = True

    except Exception:
        print("DOWN")
        raise SystemExit(2)

print("BAD" if any_workstation_failed  else "OK")
