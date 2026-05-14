from typing import Optional, Any
from pathlib import Path
from config import DEBUG

def display_results(results: dict, filename: str, hashes: list, vt_results: list) -> None:
    print("*** Simple Email Phishing Analyzer ***")
    print("=== File Info ===")
    print_field("Email: ", filename)
    print_field("Size: ", f"{Path(filename).stat().st_size} bytes")
    print("\n=== Header Analysis ===")
    print_field("Subject: ", results.get("subject", "None"))
    print_field("From: ", results["display_name_spoof"].get("display_name", "None"))
    print_field("Domain: ", results["display_name_spoof"].get("from_domain", "None"))
    print_field("Reply-To: ", results["reply_to"].get("replyto_domain", "None"))
    print_field("Origin Domain: " , results["received_chain"].get("origin_domain", "None"))
    print_field("Hops: " , results["received_chain"].get("hops", "None"))
    print("\nAuthentication")
    print_field("   spf: ", results.get("spf", "none"))
    print_field("   dkim: ", results.get("dkim", "none"))
    print_field("   dmarc: ", results.get("dmarc", "none"))
    print("\n=== Findings ===")
    print_field("Display Name Spoof: ", verdict(results["display_name_spoof"]["spoofed"]))
    print_field("Reply-To Mismatch: " , verdict(results["reply_to"]["mismatch"]))
    print_field("Received Chain Mismatch: " , verdict(results["received_chain"].get("mismatch", "None")))
    
    print("\n=== URL Analysis ===")
    if vt_results:
        for vt_result in vt_results:
            if vt_result.get("error"):
                print_field("URL: ", vt_result["url"])
                print_field("Error: ", vt_result["error"])
            else:
                print_field("URL: ", vt_result["url"])
                print_field("Verdict: ", url_verdict(vt_result["malicious"], vt_result["suspicious"]))
                print_field("Malicious: ", vt_result["malicious"])
                print_field("Suspicious: ", vt_result["suspicious"])
    else:
        print("No URLS found.")

    print("\n=== Attachment Analysis ===")    
    if hashes:
        for h in hashes:
            print_field("filename: ", h["filename"])
            print_field("content-type: ", h["content_type"])
            print_field("md5: ", h["md5"])
            print_field("sha1: ", h["sha1"])
            print_field("sha256: ", h["sha256"])
    else:
        print("No attachments found.")





def print_field(label: str, value: Any) -> None:
    print(f"{label:<30} {value}")

# Translate Spoofed and Mismatch from True/False/None to FLAGGED/CLEAN/N/A
def verdict(value: Optional[bool]) -> str:
    if value is True:
        return "FLAGGED"
    elif value is False:
        return "CLEAN"
    return "N/A"

def url_verdict(malicious: int, suspicious: int) -> str:
    if malicious >= 1:
        return "MALICIOUS"
    elif suspicious >= 1:
        return "SUSPICIOUS"
    return "CLEAN"