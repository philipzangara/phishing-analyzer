from typing import Optional, Any
from pathlib import Path
from config import DEBUG

def display_results(results: dict, filename: str, hashes: list, vt_results: list, mb_results: list) -> None:
    print("*** Simple Email Phishing Analyzer ***")
    print("=== File Info ===")
    print_field("Email: ", filename)
    print_field("Size: ", f"{Path(filename).stat().st_size} bytes")
    print("\n=== Header Analysis ===")
    print_field("Subject: ", results.get("subject", "N/A"))
    print_field("From: ", results["display_name_spoof"].get("display_name", "N/A"))
    print_field("Domain: ", results["display_name_spoof"].get("from_domain", "N/A"))
    print_field("Reply-To: ", results["reply_to"].get("replyto_domain", "N/A"))
    print_field("Origin Domain: " , results["received_chain"].get("origin_domain", "N/A"))
    print_field("Hops: " , results["received_chain"].get("hops", "N/A"))
    print("\nAuthentication")
    print_field("   SPF: ", results.get("spf", "N/A"))
    print_field("   DKIM: ", results.get("dkim", "N/A"))
    print_field("   DMARC: ", results.get("dmarc", "N/A"))
    print("\n=== Findings ===")
    print_field("Display Name Spoof: ", verdict(results["display_name_spoof"]["spoofed"]))
    print_field("Reply-To Mismatch: " , verdict(results["reply_to"]["mismatch"]))
    print_field("Received Chain Mismatch: " , verdict(results["received_chain"].get("mismatch", "N/A")))
    
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
            print_field("Filename: ", h["filename"])
            print_field("Content-Type: ", h["content_type"])
            print_field("MD5: ", h["md5"])
            print_field("SHA1: ", h["sha1"])
            print_field("SHA256: ", h["sha256"])
    else:
        print("No attachments found.")

    print("\n=== MalwareBazaar Analysis ===")
    if mb_results:
        for result in mb_results:
            print_field("Filename:", result["filename"])
            print_field("SHA256:", result["sha256"])
            if result.get("error"):
                print_field("Error:", result["error"])
            elif result["found"]:
                print_field("Verdict:", "FOUND - MALICIOUS")
                print_field("Malware Name:", result["malware_name"])
            else:
                print_field("Verdict:", "Not found in MalwareBazaar")
    else:
        print("No attachments to check.")



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