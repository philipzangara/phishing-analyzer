# A Simple email parsing tool

import argparse 
import sys
from pathlib import Path
from email import message_from_binary_file
from email import policy
from email.utils import parseaddr
import tldextract

DEBUG = False

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Process a filename.")
    parser.add_argument("filename", help="Path to the file to process")
    return parser.parse_args(argv)

def parse_headers(msg):
    if DEBUG:
        print(msg['From'])
        print(msg['Subject'])
        print(msg.get_all('Received'))

def parse_body(msg):
    for part in msg.walk():
        if part.get_content_type().startswith("multipart"): 
            continue
        elif part.get_content_type() == "text/plain":
            plain = part.get_payload(decode=True)
            charset = part.get_content_charset()
            if charset == None:
                charset = 'utf-8'
            text = plain.decode(charset, errors='replace')
            if DEBUG: print(text[:200])
            continue
        elif part.get_content_type() == "text/html":
            html = part.get_payload(decode=True)
            charset = part.get_content_charset()
            if charset == None:
                charset = 'utf-8'
            text = html.decode(charset, errors='replace')
            if DEBUG: print(text[:200])
            
def parse_attachments(msg):
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            if DEBUG: print(part.get_filename())
            if DEBUG: print("Attachment") 
    
def analyze_headers(msg):
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
    if DEBUG: print(results)
    return results

# Check is the display name is similar to the domain name, ex. "Microsoft Support" and info@microsoft.com
# Matches on the first word found in domain - TLD not evaluated here.
def check_display_name_spoof(msg):
    name, addr = parseaddr(msg['From'])

    # If display_name is not empty
    if name:
        extract = tldextract.extract(addr)
        name_split = name.split(' ')

        # check if ... name is the same as the extracted domain name
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
def check_reply_to(msg):
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
def print_field(label, value):
    print(f"{label:<20} {value}")

# Translate Spoofed and Mismatch from True/False/None to FLAGGED/CLEAN/N/A
def verdict(value):
    if value is True:
        return "FLAGGED"
    elif value is False:
        return "CLEAN"
    return "N/A"

def display_results(results, filename):
    print("*** Simple Email Phishing Analyzer ***")
    print("=== File Info ===")
    print_field("Email: ", filename)
    print_field("Size:", f"{Path(filename).stat().st_size} bytes")
    print("\n=== Header Analysis ===")
    print_field("Subject: ", results.get("subject", "None"))
    print_field("From: ", results["display_name_spoof"].get("display_name", "None"))
    print_field("Domain: ", results["display_name_spoof"].get("from_domain", "None"))
    print_field("Reply-To: ", results["reply_to"].get("replyto_domain", "None"))
    print("\nAuthentication")
    print_field("   spf: ", results.get("spf", "none"))
    print_field("   dkim: ", results.get("dkim", "none"))
    print_field("   dmarc: ", results.get("dmarc", "none"))
    print("\n=== Findings ===")
    print_field("Display Name Spoof: ", verdict(results["display_name_spoof"]["spoofed"]))
    print_field("Reply-To Mismatch: " , verdict(results["reply_to"]["mismatch"]))
    

def main(argv=None):
    args = parse_args(argv)
    filename = args.filename
    file_ext = Path(args.filename)
    if file_ext.suffix.lower() not in [".eml"]:
        print("Error: Email must have .eml extention", file=sys.stderr)
        raise SystemExit(2)

    with open(filename, 'rb') as f:
        msg = message_from_binary_file(f, policy=policy.default)

    parse_headers(msg)
    parse_body(msg)
    parse_attachments(msg)
    header_results = analyze_headers(msg)
    display_results(header_results,filename)

if __name__ == "__main__":
    main()