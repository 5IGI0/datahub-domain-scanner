import dns.resolver
import random
import string

def dns_scan(data, domain):
    data["dns_records"] = {}

    for qtype in ["A", "AAAA", "MX"]:
        try:
            answer = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            answer = []
        except dns.resolver.NoAnswer:
            answer = []
        except dns.resolver.NoNameservers:
            return
        except dns.resolver.LifetimeTimeout:
            return
        if len(answer):
            data["tags"].append({
                "A":    "IPv4",
                "AAAA": "IPv6",
                "MX":   "mail"
            }[qtype])
            answers = []
            for a in answer:
                answers.append(str(a))
            data["dns_records"][qtype] = answers

    try:
        rnd_subdomain = ''.join(random.choices(string.ascii_lowercase,k=10))
        dns.resolver.resolve_name(rnd_subdomain+"."+domain, tcp=True)
        data["tags"].append("subdomain-wildcard")
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NoNameservers:
        pass
