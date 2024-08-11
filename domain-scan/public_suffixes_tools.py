from public_suffixes_list import public_suffixes

def merge_tld(labels):
    for i in range(len(labels)):
        parts = labels[i:len(labels)]
        tld = ".".join(parts)
        if tld in public_suffixes:
            return labels[:i] + [tld]
        # i see some suffixes with "*." so i guess i have to do something like that
        # (too lazy to read the doc)
        if ".".join(["*"] + parts[1:]) in public_suffixes:
            return labels[:i] + [tld]
    return labels