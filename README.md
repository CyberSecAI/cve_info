# Overview

For a given CVE Description, the following is available in the json file for that CVE:
1. description: original CVE Description
2. keyphrases: Vulnerability Key Phrases per https://www.cve.org/Resources/General/Key-Details-Phrasing.pdf
3. mitre_technical_impacts: The Impact(s) mapped to MITRE Technical Impacts per https://cwe.mitre.org/community/swa/priority.html 


## Example: CVE-2020-3118
https://github.com/CyberSecAI/cve_info/blob/main/2020/3xxx/CVE-2020-3118.json
````
{
    "description": "A vulnerability in the Cisco Discovery Protocol implementation for Cisco IOS XR Software could allow an unauthenticated, adjacent attacker to execute arbitrary code or cause a reload on an affected device. The vulnerability is due to improper validation of string input from certain fields in Cisco Discovery Protocol messages. An attacker could exploit this vulnerability by sending a malicious Cisco Discovery Protocol packet to an affected device. A successful exploit could allow the attacker to cause a stack overflow, which could allow the attacker to execute arbitrary code with administrative privileges on an affected device. Cisco Discovery Protocol is a Layer 2 protocol. To exploit this vulnerability, an attacker must be in the same broadcast domain as the affected device (Layer 2 adjacent).",
    "keyphrases": {
        "rootcause": "improper validation of string input",
        "weakness": "stack overflow",
        "impact": [
            "execute arbitrary code",
            "cause a reload"
        ],
        "vector": "malicious Cisco Discovery Protocol packet",
        "attacker": "unauthenticated adjacent attacker",
        "product": "Cisco IOS XR Software",
        "version": "",
        "component": "Cisco Discovery Protocol implementation"
    },
    "mitre_technical_impacts": [
        "Execute unauthorized code or commands",
        "Modify data"
    ]
}
````

## Example: CVE-2020-9054
https://github.com/CyberSecAI/cve_info/blob/main/2024/4xxx/CVE-2024-4610.json


````
{
    "description": "Use After Free vulnerability in Arm Ltd Bifrost GPU Kernel Driver, Arm Ltd Valhall GPU Kernel Driver allows a local non-privileged user to make improper GPU memory processing operations to gain access to already freed memory.This issue affects Bifrost GPU Kernel Driver: from r34p0 through r40p0; Valhall GPU Kernel Driver: from r34p0 through r40p0.",
    "keyphrases": {
        "rootcause": "use after free",
        "weakness": "",
        "impact": "gain access to already freed memory",
        "vector": "improper GPU memory processing operations",
        "attacker": "local non-privileged user",
        "product": [
            "Arm Ltd Bifrost GPU Kernel Driver",
            "Arm Ltd Valhall GPU Kernel Driver"
        ],
        "version": [
            "from r34p0 through r40p0",
            "from r34p0 through r40p0"
        ],
        "component": ""
    },
    "mitre_technical_impacts": [
        "Execute unauthorized code or commands",
        "Bypass protection mechanism"
    ]
}
````



## Files
CVE files are allocated to directories by year per
1. https://github.com/cisagov/vulnrichment
2. https://github.com/CVEProject/cvelistV5/tree/main/cves

This avoids having MANY files in one directory making it harder to browse through.