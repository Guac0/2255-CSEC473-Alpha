


import socket
import sys
import urllib.error
import urllib.request


url = "http://10.0.10.3/doku.php?id=wiki:wikipage"


def check_url(target_url, timeout=5.0, expected_text=None):
    req = urllib.request.Request(target_url, headers={"User-Agent": "apacheScoreCheck/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None)
            body = resp.read()
            # try to decode using charset header if provided, otherwise utf-8
            charset = None
            try:
                content_type = resp.headers.get_content_charset()
                if content_type:
                    charset = content_type
            except Exception:
                charset = None
            try:
                text = body.decode(charset or "utf-8", errors="replace")
            except Exception:
                text = body.decode("utf-8", errors="replace")

            if expected_text:
                if expected_text in text:
                    return True, f"UP (status={status}) MATCHED_TEXT", 0
                else:
                    return False, "MISSING_TEXT", 3

            if status is None:
                return True, "UP (no status available)", 0
            if 200 <= status < 400:
                return True, f"UP (status={status})", 0
            return False, f"UNEXPECTED_STATUS (status={status})", 2
    except urllib.error.HTTPError as e:
        return False, f"HTTP_ERROR {getattr(e, 'code', '')} {getattr(e, 'reason', '')}", 1
    except urllib.error.URLError as e:
        return False, f"URL_ERROR {getattr(e, 'reason', '')}", 1
    except socket.timeout:
        return False, "TIMEOUT", 1
    except Exception as e:
        return False, f"ERROR {e}", 1


def main():
   

    up, message, code = check_url(url, timeout=5.0, expected_text=None)
    if up:
        print(f"OK: {message}")
        sys.exit(0)
    else:
        print(f"FAIL: {message}")
        sys.exit(code if isinstance(code, int) else 1)


if __name__ == "__main__":
    main()






