import subprocess

def check (website:str, text:str) -> bool:
    res = subprocess.run(
        ["curl", website],
        capture_output=True,
        text=True
    )

    if res.returncode != 0: return False

    if text in res.stdout: return True

    return False
