# A Simple email parsing tool

import argparse 
import sys
from pathlib import Path
from email import message_from_binary_file
from email import policy
from email.message import Message

from headers import analyze_headers
from body import parse_body, extract_urls
from attachments import parse_attachments, hash_attachments
from vt import check_urls_vt
from display import display_results
from malwarebazaar import check_hashes_malwarebazaar
from scoring import calculate_score
from config import DEBUG

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Process a filename.")
    parser.add_argument("filename", help="Path to the file to process")
    return parser.parse_args(argv)

def parse_headers(msg: Message) -> None:
    if DEBUG:
        print("Headers")
        print(msg['From'])
        print(msg['Subject'])
        print(msg.get_all('Received'))
        
def main(argv=None) -> None:
    args = parse_args(argv)
    filename = args.filename
    file_ext = Path(args.filename)
    if file_ext.suffix.lower() not in [".eml"]:
        print("Error: Email must have .eml extension", file=sys.stderr)
        raise SystemExit(2)

    with open(filename, 'rb') as f:
        msg = message_from_binary_file(f, policy=policy.default)

    parse_headers(msg)
    body = parse_body(msg)
    urls = extract_urls(body)
    vt_results = check_urls_vt(urls)
    attachments = parse_attachments(msg)
    hashes = hash_attachments(attachments)
    mb_results = check_hashes_malwarebazaar(hashes)
    header_results = analyze_headers(msg)
    score = calculate_score(header_results, vt_results, mb_results)
    display_results(header_results, filename, hashes, vt_results, mb_results, score)

if __name__ == "__main__":
    main()