import requests
import json

l = requests.get("https://publicsuffix.org/list/public_suffix_list.dat").text.split("\n")

cleaned_list = []

for e in l:
    #print(e)
    e = e.split("//")[0].strip()
    if e != "":
        cleaned_list.append(e)

with open("domain-scan/public_suffixes_list.py", "w") as fp:
    fp.write("public_suffixes = "+json.dumps(cleaned_list, indent=4))
