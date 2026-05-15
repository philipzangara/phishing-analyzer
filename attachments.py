from email.message import Message
import hashlib
from config import DEBUG

def parse_attachments(msg: Message) -> list:

    attachments = []

    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            if DEBUG: print("Attachment File Name: ", part.get_filename())
            attachments.append({"filename": part.get_filename(),
                                "content_type": part.get_content_type(),
                                "data": part.get_payload(decode=True)
                                 })
            
    return attachments

def hash_attachments(attachments: list) -> list:

    hashes = []

    for attachment in attachments:
        hashes.append({"filename": attachment["filename"],
                        "content_type": attachment["content_type"],
                        "md5": hashlib.md5(attachment["data"]).hexdigest(),
                        "sha1": hashlib.sha1(attachment["data"]).hexdigest(),
                        "sha256": hashlib.sha256(attachment["data"]).hexdigest(),
                         })
        
    return hashes
 