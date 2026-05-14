from email.message import Message
import hashlib
from config import DEBUG

def parse_attachments(msg: Message) -> None:
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            if DEBUG: print(part.get_filename())
            if DEBUG: print("Attachment") 