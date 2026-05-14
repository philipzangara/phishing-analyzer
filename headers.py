from email.utils import parseaddr
from email.message import Message
import tldextract
from typing import Optional, Any
from config import DEBUG

def analyze_headers(msg: Message) -> dict:
    auth_fields = ["spf", "dkim", "dmarc"]
    results = {}
    headers = msg.get_all('Authentication-Results', [])
    parts = [p.strip() for p in headers[0].split(";") if p.strip()] if headers else []
    for part in parts:
        for af in auth_fields:
            if part.startswith(af + "="):
                result = part.split(" ", 1)[0]
                final_result = result.split("=", 1)
                results[final_result[0]] = final_result[1]

    results["display_name_spoof"] = check_display_name_spoof(msg)
    results["reply_to"] = check_reply_to(msg)
    results["subject"] = msg["Subject"]
    results["received_chain"] = received_chain_analysis(msg)
    if DEBUG: print(results)
    return results

# Check is the display name is similar to the domain name, ex. "Microsoft Support" and info@microsoft.com
# Matches on the first word found in domain - TLD not evaluated here.
def check_display_name_spoof(msg: Message) -> dict:
    name, addr = parseaddr(msg['From'])

    # If display_name is not empty
    if name:
        extract = tldextract.extract(addr)
        name_split = name.split(' ')

        # check if display name is the same as the extracted domain name
        for n in name_split:
            if n.lower() in extract.domain:
                return { 
                    "spoofed": False,
                    "display_name": name,
                    "from_domain": extract.domain+"."+extract.suffix 
                    }
        return { 
            "spoofed": True, 
            "display_name": name, 
            "from_domain": extract.domain+"."+extract.suffix 
            }

    return { 
        "spoofed": None, 
        "reason": "No display name present"
        }

# Check if the Reply-To address matches the From address
def check_reply_to(msg: Message) -> dict:
    if msg['Reply-To']:
        _, reply_addr = parseaddr(msg['Reply-To'])
        _, from_addr = parseaddr(msg['From'])
        reply_extract = tldextract.extract(reply_addr)
        from_extract = tldextract.extract(from_addr)
        if reply_extract.domain == from_extract.domain:
            return {
                "mismatch": False, 
                "from_domain":from_extract.domain+"."+from_extract.suffix, 
                "replyto_domain": reply_extract.domain+"."+reply_extract.suffix
                }
        else:
            return {
                "mismatch": True, 
                "from_domain":from_extract.domain+"."+from_extract.suffix, 
                "replyto_domain": reply_extract.domain+"."+reply_extract.suffix
                }
        
    return {
        "mismatch": None,
        "reason": "No Reply-To header"
        }

# received gets a header similar to "from 2435sdf.co.uk (X.X.X.X) by DM6NAFSDTM11FT012.mail.protection.outlook.com ...."
# The last item of the array is the first hop
# Split the array, the "from" is the [0] item of the array, then the domain is the [1] item
def received_chain_analysis(msg: Message) -> dict:
    received = msg.get_all('Received')

    if not received:
        return {"mismatch": None, "reason": "No Received headers"} 
    
    received_split = received[-1].split()
    received_extract = tldextract.extract(received_split[1])

    _, from_addr = parseaddr(msg['From'])
    from_extract = tldextract.extract(from_addr)

    mismatch = None
    if (from_extract.domain+"."+from_extract.suffix == received_extract.domain+"."+received_extract.suffix):   
        mismatch = False     
    else:
        mismatch = True
    
    return {
        "origin_domain": received_extract.domain+"."+received_extract.suffix,
        "from_domain": from_extract.domain+"."+from_extract.suffix,
        "mismatch": mismatch,
        "hops": len(received)
    }