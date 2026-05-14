import requests
import base64
import time
import os
from dotenv import load_dotenv
from config import DEBUG

load_dotenv()
api_key = os.getenv("VT_API_KEY")

# check URLS in VirusTotal
# rate limit to 15 seconds. Only 4 free API calls per minute.
def check_urls_vt(urls: list) -> list:
    vt_results = []

    for url in urls:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')

        headers = {"x-apikey": api_key}
        data = {"url": url} 
        post_response = requests.post("https://www.virustotal.com/api/v3/urls", 
                                  headers=headers, data=data)
        
        if post_response.status_code != 200:
            vt_results.append({"url": url, "error": f"POST failed: {post_response.status_code}"})
        else:
            get_response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", 
                                headers=headers)
            try:
                response = get_response.json()
                stats = response["data"]["attributes"]["last_analysis_stats"]
                vt_results.append({
                    "url": url,
                    "malicious": stats["malicious"],
                    "suspicious": stats["suspicious"],
                    "harmless": stats["harmless"]
                })
            except Exception as e:
                vt_results.append({
                    "url": url,
                    "error": str(e)
                })
        time.sleep(15)    
    return vt_results