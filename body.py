import re
from bs4 import BeautifulSoup
from email.message import Message
from config import DEBUG

# Iterates through the body of the email
# This will only return the body of the email the receiver first sees
def parse_body(msg: Message) -> dict:
    body = {"plain": "", "html": ""}
    for part in msg.walk():
        if part.get_content_type().startswith("multipart"): 
            continue
        elif part.get_content_type() == "text/plain":
            plain = part.get_payload(decode=True)
            charset = part.get_content_charset()
            if charset == None:
                charset = 'utf-8'
            text = plain.decode(charset, errors='replace')
            if body["plain"] == "":
                body["plain"] = text
            if DEBUG: print(text[:200])
            continue
        elif part.get_content_type() == "text/html":
            html = part.get_payload(decode=True)
            charset = part.get_content_charset()
            if charset == None:
                charset = 'utf-8'
            text = html.decode(charset, errors='replace')
            if body["html"] == "":
                body["html"] = text
            if DEBUG: print(text[:200])
    return body

def extract_urls(body: dict) -> list:
    url_strip = []
    soup_body = BeautifulSoup(body["html"], 'html.parser')

    # extract urls from the plain text and cleaned html text
    # strip extra punctuation from the end of a url
    for text in [body["plain"], soup_body.get_text()]:
        for u in re.findall(r'https?://\S+', text):
            url_strip.append(u.rstrip('.,;:)"'))

    # extract urls from <a> tags
    # the regex might miss a URL, so we use BeautifulSoup to
    # find the rest
    # strip extra punctuation from the end of a url
    for link in soup_body.find_all('a'):
        href = link.get('href')
        if href and href.startswith('http'):
            url_strip.append(href.rstrip('.,;:)"'))

    # extract urls from <img> tags
    for img in soup_body.find_all('img'):
        src = img.get('src')
        if src and src.startswith('http'):
            url_strip.append(src.rstrip('.,;:)"'))

    # converting to a set removes duplicates, then return back to a list
    return list(set(url_strip))