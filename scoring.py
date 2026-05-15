def calculate_verdict(score: int):
    if score <= 20:
        return "LOW"
    elif score <= 50:
        return "MEDIUM"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"

def calculate_score(header_results: dict, vt_results: list, mb_results: list) -> dict:

    score = 0
    reasons = []

    # Authentication score
    if header_results.get("spf", "N/A") == "fail":
        score += 10
        reasons.append("SPF fail")
    elif header_results.get("spf", "N/A") == "softfail":
        score += 5
        reasons.append("SPF softfail")
    
    if header_results.get("dkim", "N/A") == "fail":
        score += 15
        reasons.append("DKIM fail")

    if header_results.get("dmarc", "N/A") == "fail":
        score += 20
        reasons.append("DMARC fail")

    # Header score
    if header_results["display_name_spoof"]["spoofed"] is True:
        score += 20
        reasons.append("Display Name Spoof")
    
    if header_results["reply_to"]["mismatch"] is True:
        score += 25
        reasons.append("Reply-To Mismatch")
    
    if header_results["received_chain"].get("mismatch") is True:
        score += 20
        reasons.append("Received Chain Mismatch")

    # URL/Attachment score
    for vt_result in vt_results:
        if vt_result.get("malicious", 0) >= 1:
            score += 60
            reasons.append(f"Malicious URL: {vt_result['url']}")

    for mb_result in mb_results:
        if mb_result.get("found") is True:
            score += 70
            reasons.append(f"Malicious attachment: {mb_result['filename']}")

    return {
        "score": score, 
        "verdict": calculate_verdict(score),
        "reasons": reasons
    }