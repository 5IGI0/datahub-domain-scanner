import whois
import dns.resolver
import json
from dns_scanner import dns_scan
from http_scanner import http_scan
from datetime import datetime, timezone
from constants import SCANNER_VER, THREAD_COUNT, TOR_PROXY
import threading
import queue
import os
import traceback

os.makedirs("./crash-reports/", exist_ok=True)

dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ["8.8.8.8"]
dns.resolver.default_resolver.timeout=5.0
dns.resolver.default_resolver.lifetime=5.0

def start_scan(domain):
    domain = domain.strip()
    data = {
    "domain": domain,
    "version": SCANNER_VER,
    "tags": [],
    "services": {},
    "records": {},
    "meta": {
        "nameservers": dns.resolver.default_resolver.nameservers,
        "started_at": datetime.now(timezone.utc).isoformat()
    }}

    try:
        # imagine going to jail because of DNS leak, lol
        # TODO: support hidden-services
        while len(domain) and domain.endswith("."):
            domain = domain[:-1]

        if (
            domain == "" or
            (domain.endswith(".onion") and TOR_PROXY is None) or 
            domain.endswith(".i2p")     or
            # TODO: check if .zero is zeronet's TLD
            domain.endswith(".zero")):
            data["meta"]["ended_at"] = datetime.now(timezone.utc).isoformat()
            return data

        if not domain.endswith(".onion"):
            print("whois", flush=True)
            try:
                data["whois"] = whois.whois(domain).text
            except:
                pass
            print("dns_scan", flush=True)
            dns_scan(data, domain)
        else:
            data["whois"] = "[no whois for tor sites]"
            data["dns_records"] = {}


        # no point to try to perform service scan if no IP is associated (or tor)
        if "IPv4" in data["tags"] or "IPv6" in data["tags"] or domain.endswith(".onion"):
            print("http", flush=True)
            http_scan(data, domain, False)
            print("http", flush=True)
            http_scan(data, domain, True)
    except Exception as e:
        with open(f"crash-reports/{datetime.now().isoformat()}-{domain[:30]}.txt", "w") as f:
            traceback.TracebackException.from_exception(e).print(file=f)
            f.write("\n\n")
            f.write("scan data: ")
            try:
                json.dump(data, f)
            except:
                f.write("[ERROR]\n")
                f.write("stringified: "+str(data)+"\n")
        data["meta"]["error"] = str(e)
        data["tags"].append("crashed-scan")
    data["meta"]["ended_at"] = datetime.now(timezone.utc).isoformat()
    return data

if __name__ == "__main__":
    import sys
    import requests
    import time

    if sys.argv[1] == "scan":
        print(json.dumps(start_scan(sys.argv[2]), indent=4))
    elif sys.argv[1] == "worker":
        domain_queue = queue.Queue()

        current_domain_lock = threading.Lock()
        current_domain_scans = []
        def worker():
            while 1:
                domain = domain_queue.get()
                with current_domain_lock:
                    if domain in current_domain_scans:
                        continue
                    else:
                        current_domain_scans.append(domain)
                data = start_scan(domain)
                print("data: ", data)
                print("response:", requests.post(sys.argv[2]+"/api/v1/domains/add_scan", headers={"Authorization": "Bearer "+sys.argv[3]}, json=data).text, flush=True)
                with current_domain_lock:
                    current_domain_scans.remove(domain)

        threads = [
            threading.Thread(target=worker,args=())for _ in range(THREAD_COUNT)
        ]

        for thread in threads:
            thread.start()

        while True:
            print("fetching more domains...")
            response = requests.get(sys.argv[2]+"/api/v1/domains/outdated", headers={"Authorization": "Bearer "+sys.argv[3]}).json()

            if len(response["data"]) == 0:
                print("no outdated domain, waiting...")
                time.sleep(30)
                continue

            for domain in response["data"]:
                domain_queue.put(domain)

            while not domain_queue.empty():
                time.sleep(5)
            time.sleep(20) # waiting for all scans to finish
