import requests
import uuid
import urllib.parse
from bs4 import BeautifulSoup
from public_suffixes_tools import merge_tld
from certificate_dumper import dump_certificate
from atomic import SafeFileAppender

# TODO: decode domains (IDNA) before comparing them

links_list = SafeFileAppender("links.txt")

META_PROPERTY_BLACKLIST=[
    "video:duration", "og:image:type", "og:image:height",
    "og:image:width", "twitter:card"]

default_headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
}

default_request_config = {
    "timeout": (5,5),
    "allow_redirects": False
}

def http_scan(data,host, scan_on_https):
    sess = requests.session()
    sess.verify = False
    sess.headers.update(default_headers)
    schema = "http" if not scan_on_https else "https"
    host = host.lower()

    print("initial req", flush=True)
    try:
        response = sess.get(f"{schema}://{host}", **default_request_config)
    except:
        return

    data["services"][schema] = {"tags": []}

    if scan_on_https:
        data["services"][schema]["certificate"] = dump_certificate(host, 443)

    # if we get a redirection, we check for dumb redirection
    # because if it is, then there is no point to perform advanced scan
    if response.status_code > 299 and response.status_code <= 399:
        print("redirect check", flush=True)
        is_dumb_redirect = check_redirection(data,host,schema,sess,response)
        if is_dumb_redirect or "dumb-redirect" in data["services"][schema]["tags"]:
            data["services"][schema]["redirect_target"] = response.headers.get("Location")
            home_page_scan(data, host, schema, sess, response)
            return
        
        print("follow redirect", flush=True)
        old_respone = response
        response, tag = follow_local_redirections(schema, host, f"{schema}://{host}", response, sess)
        if response is None:
            home_page_scan(data, host, schema, sess, old_respone)
            robots_txt_scan(data, host, schema, sess)
            data["services"][schema]["tags"].append(tag)
            return
    
    print("robots", flush=True)
    robots_txt_scan(data, host, schema, sess)
    print("home page", flush=True)
    home_page_scan(data, host, schema, sess, response)

def check_redirection(data, host, schema, sess, response):
    location = response.headers.get("Location")

    # ???
    if location is None:
        data["services"][schema]["tags"].append("invalid-redirect")
        return True

    # TODO: check how to interpret "//" location
    #       (redirection to same-schema site (like html) or local resource?)
    if schema == "http" and (location.lower().startswith(f"https://{host}/") or location.lower() == f"https://{host}"):
        data["services"][schema]["tags"].append("https-redirect")
    elif location.lower().startswith(f"{schema}://{host}/") or location.startswith("/") or not "://" in location:
        data["services"][schema]["tags"].append("local-redirect")
    else:
        data["services"][schema]["tags"].append("external-redirect")

    return check_dumb_redirection(data, host, schema, sess)


def check_dumb_redirection(data, host, schema, sess):
    # 3 cases of dumb redirection:
    # 1. redirecting always to the same URL
    # 2. redirecting always to another domain/schema, keeping path
    #    (www.example.com -> example.com or http://... -> https://...)
    # 3. redirecting always to https://some_site.tld/login.php?path=/amazing/path/to/that/resource.txt
    #
    # so i think the best way to avoid most false-negative is to check
    # if it redirects to an external link when reaching random pages.
    # (if it performs local redirection, then it should have some sort of logic behind it)

    try:
        response = sess.get(f"{schema}://{host}/{uuid.uuid4()}", **default_request_config)
    except:
        return True

    location = response.headers.get("Location")
    # Let's assume the server doesn't reply broken redirection
    if location is None:
        return False

    if location.lower().startswith(f"{schema}://{host}/") or location.startswith("/") or not "://" in location:
        return False

    data["services"][schema]["tags"].append("dumb-redirect")
    return True

def follow_local_redirections(schema, host, location, response, sess, max_depth=3):
    if max_depth == 0:
        return None, "exceeded-redirection-limit"

    new_location = response.headers.get("Location")

    if new_location is None:
        return response, ""

    new_location = urllib.parse.urljoin(location, new_location)

    if new_location.startswith(f"{schema}://{host}/") or new_location == f"{schema}://{host}":
        try:
            response = sess.get(new_location, **default_request_config)
        except:
            return None, "conn-error"
        if response.headers.get("Location"):
            return follow_local_redirections(schema, host, new_location, response, sess,
                max_depth=max_depth-1)
        else:
            return response, ""
    else:
        return None, "external-redirect"

def __is_external_link(link, host):
    # i check if both have the same domain of origin (ignoring sub-domains) because,
    # in theory, if both are part of the same domain,
    # then the webmasters have control over both
    # (so you can't really consider that as an "external" resource)
    netloc = urllib.parse.urlparse(link).netloc
    if netloc == "":
        return False

    host = (host[:-1] if host.endswith(".") else host).lower()
    netloc = (netloc[:-1] if host.endswith(".") else netloc).lower()

    if host == netloc:
        return False

    host_splitted = merge_tld(host.split("."))
    netloc_splitted = merge_tld(netloc.split("."))

    # if there's only one label, they must not be the same
    # (otherwise it would have matched in with the previous if)
    if len(host_splitted) == 1 or len(netloc_splitted) == 1:
        return True

    return not  (host_splitted[0] == netloc_splitted[0] and
                host_splitted[1] == netloc_splitted[1])

def home_page_scan(data, host, schema, sess, response):
    data["services"][schema]["path"] = '/'.join(response.url.split("/")[3:])
    data["services"][schema]["status_code"] = response.status_code
    data["services"][schema]["headers"] = dict(response.headers)
    soup = BeautifulSoup(response.content, "html.parser")
    try:
        data["services"][schema]["title"] = soup.find("title").get_text()
    except:
        data["services"][schema]["title"] = ""
    data["services"][schema]["html_meta"] = []

    # get metadata
    for meta in soup.find_all("meta"):
        if meta.has_attr("name") and meta.has_attr("content") and not meta["name"] in META_PROPERTY_BLACKLIST:
            data["services"][schema]["html_meta"].append({
                "property": meta["name"],
                "content": meta["content"]
            })
        elif meta.has_attr("property") and meta.has_attr("content") and not meta["property"] in META_PROPERTY_BLACKLIST:
            data["services"][schema]["html_meta"].append({
                "property": meta["property"],
                "content": meta["content"]
            })

    # so i can use it to discover new domains or discord/tg/...
    links = ""
    for script in soup.find_all("script"):
        if script.has_attr("src") and __is_external_link(script["src"], host):
            links += script["src"]+"\n"
    for link_elem in soup.find_all("link"):
        if link_elem.has_attr("href") and __is_external_link(link_elem["href"], host):
            links += link_elem["href"]+"\n"
    for a in soup.find_all("a"):
        if a.has_attr("href") and __is_external_link(a["href"], host):
            links += a["href"]+"\n"
    for img in soup.find_all("img"):
        if img.has_attr("src") and __is_external_link(img["src"], host):
            links += img["src"]+"\n"
    links_list.append(links)

def robots_txt_scan(data, host, schema, sess):
    try:
        response = sess.get(f"{schema}://{host}/robots.txt", **default_request_config)
    except:
        return
    
    if response.status_code != 200:
        return

    current_useragent = "*"
    directives = []

    for line in response.text.split("\n"):
        line = line.split("#")[0].strip()
        
        line = line.split(": ")
        if len(line) < 2:
            continue

        directive_name = line[0]
        directive_data = ': '.join(line[1:])

        if len(directive_name) > 64 or len(directive_data) > 255 or " " in directive_name:
            return

        if directive_name.lower() == "user-agent":
            current_useragent = directive_data.strip()
            continue

        directives.append({
            "useragent": current_useragent,
            "directive": directive_name.strip(),
            "data": directive_data.strip()
        })

        if len(directives) > 250:
            break

    data["services"][schema]["robots_txt"] = directives

