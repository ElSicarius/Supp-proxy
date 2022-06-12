# Supp-proxy
Wassup proxy ? A tool to help you pentest hard to automate endpoints


# Added options from supp-truder

## Test any url in the headless chromium

```bash
/usr/bin/chromium-browser --remote-debugging-port=9222

supp-proxy.py -u "§" --chrome-debug-port 9222 --proxy-port 8081 
    curl -ski "http://127.0.0.1:8081/headless?sup=http://test.machin.tld/aaa" --proxy 127.0.0.1:8080 
```
```bash
supp-proxy.py -u "https://ssrf.site/jwtVulnerable.php?id=§" --chrome-debug-port 9222 --proxy-port 8081 -T jwtEncodeApp -T base64  
    curl -ski "http://127.0.0.1:8081/headless?sup=vuln_exploitation" --proxy 127.0.0.1:8080 

```