# Overview

For a given CVE Description, the following is available in the json file for that CVE:
1. description: original CVE Description
2. keyphrases: Vulnerability Key Phrases per https://www.cve.org/Resources/General/Key-Details-Phrasing.pdf
3. mitre_technical_impacts: The Impact(s) mapped to MITRE Technical Impacts per https://cwe.mitre.org/community/swa/priority.html 


CVE files are allocated to directories by year per
1. https://github.com/cisagov/vulnrichment
2. https://github.com/CVEProject/cvelistV5/tree/main/cves

This avoids having MANY files in one directory making it harder to browse through.