# A Simple email parsing tool

import argparse 
import sys
from pathlib import Path
from email import message_from_binary_file
from email import policy

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Process a filename.")
    parser.add_argument("filename", help="Path to the file to process")
    return parser.parse_args(argv)

def parse_headers(msg):
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
            print(text[:200])
            continue
        elif part.get_content_type() == "text/html":
            html = part.get_payload(decode=True)
            charset = part.get_content_charset()
            if charset == None:
                charset = 'utf-8'
            text = html.decode(charset, errors='replace')
            print(text[:200])
            
def parse_attachements(msg):
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            print(part.get_filename())
            print("Attachement") 
    

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
    parse_attachements(msg)

if __name__ == "__main__":
    main()