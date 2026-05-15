A Python-based phishing email analyzer that parses .eml files and performs 
automated triage including header analysis, URL extraction with VirusTotal 
enrichment, attachment hashing with MalwareBazaar lookup, and risk scoring.

Usage:
```
python phishing_analyzer.py <path-to-file.eml>
```
Tested using Python 3.10.11

Requirements:
```
pip install -r requirements.txt
```
Sample Data:

Test emails sourced from: https://github.com/rf-peixoto/phishing_pot/

Features

✅ 1. Email Parsing

✅ 2. Header Analysis

✅ 3. URL Extraction 

✅ 4. Attachment Analysis

✅ 5. Scoring and Report

Sample Output

![Sample Output](assets/screenshot.png)

Code Quality:
- Type checked with mypy
- Unit tested with unittest

Author: Philip Zangara

License: MIT

Disclaimer: Built independently, with AI used as a learning aid for guidance and debugging feedback.
