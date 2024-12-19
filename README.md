# Overview

For **258,430** CVEs, for a given CVE Description, the following is available in the json file for that CVE:
1. description: original CVE Description
2. keyphrases: Vulnerability Key Phrases **extracted from the CVE Description** per https://www.cve.org/Resources/General/Key-Details-Phrasing.pdf
   1. https://cwe.mitre.org/documents/cwe_usage/guidance.html provides guidance on the usage of these keyphrases.
3. Optional: mitre_technical_impacts: The Impact(s) mapped to MITRE Technical Impacts per https://cwe.mitre.org/community/swa/priority.html 

> [!TIP] 
> Some CVE Descriptions do not contain all the vulnerability information. Additional information may be in reference links (a significant portion of which are dead), or elsewhere in the CVE schema.
>
> This repo deliberately contains the Vulnerability Key Phrases **extracted from the CVE Description only**.

<p align="center">
<img src="./images/keyphrase_extract.jpg" width=50% height=50%>
<p>

## License

> [!NOTE]  
>This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License.
> - https://creativecommons.org/licenses/by-sa/4.0/


## Examples

### Example: CVE-2022-40651
https://github.com/CyberSecAI/cve_info/blob/main/2022/40xxx/CVE-2022-40651.json
````
{
    "cveId": "CVE-2022-40651",
    "version": "1.0.0",
    "timestamp": "2024-12-15T20:24:27.876763+00:00",
    "description": "This vulnerability allows remote attackers to execute arbitrary code on affected installations of Ansys SpaceClaim 2022 R1. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of X_B files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated data structure. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-17844.",
    "keyphrases": {
        "rootcause": "lack of proper validation of user-supplied data",
        "weakness": "write past the end of an allocated data structure",
        "impact": "execute arbitrary code",
        "vector": "malicious page or file",
        "attacker": "remote attackers",
        "product": "Ansys SpaceClaim",
        "version": "2022 R1",
        "component": "parsing of X_B files"
    }
}
````


### Example: CVE-2020-3118
https://github.com/CyberSecAI/cve_info/blob/main/2020/3xxx/CVE-2020-3118.json
````
{
    "cveId": "CVE-2020-3118",
    "version": "1.0.0",
    "timestamp": "2024-11-03T18:37:50.907685+00:00",
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
    "mitreTechnicalImpacts": [
        "Denial-of-Service: resource consumption",
        "Denial-of-Service: unreliable execution",
        "Execute unauthorized code or commands"
    ]
}
````

### Example: CVE-2024-4610
https://github.com/CyberSecAI/cve_info/blob/main/2024/4xxx/CVE-2024-4610.json


````
{
    "cveId": "CVE-2024-4610",
    "version": "1.0.0",
    "timestamp": "2024-11-03T18:37:50.907685+00:00",
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
    "mitreTechnicalImpacts": [
        "Bypass protection mechanism",
        "Read data"
    ]
}
````

### Example: CVE-2015-0310
https://github.com/CyberSecAI/cve_info/blob/main/2015/0xxx/CVE-2015-0310.json

````
{
    "cveId": "CVE-2015-0310",
    "version": "1.0.0",
    "timestamp": "2024-11-03T18:37:50.907685+00:00",
    "description": "Adobe Flash Player before 13.0.0.262 and 14.x through 16.x before 16.0.0.287 on Windows and OS X and before 11.2.202.438 on Linux does not properly restrict discovery of memory addresses, which allows attackers to bypass the ASLR protection mechanism on Windows, and have an unspecified impact on other platforms, via unknown vectors, as exploited in the wild in January 2015.",
    "keyphrases": {
        "rootcause": "does not properly restrict discovery of memory addresses",
        "weakness": "",
        "impact": [
            "bypass ASLR protection mechanism",
            "unspecified impact"
        ],
        "vector": "unknown vectors",
        "attacker": "attackers",
        "product": "Adobe Flash Player",
        "version": [
            "before 13.0.0.262 and 14.x through 16.x before 16.0.0.287 on Windows and OS X",
            "before 11.2.202.438 on Linux"
        ],
        "component": ""
    },
    "mitreTechnicalImpacts": [
        "Bypass protection mechanism"
    ]
}
````


## Files
CVE files are allocated to directories by year per
1. https://github.com/cisagov/vulnrichment
2. https://github.com/CVEProject/cvelistV5/tree/main/cves
3. https://github.com/CloudSecurityAlliance/gsd-database/tree/main

This avoids having MANY files in one directory making it harder to browse through.


## Schema

The files conform to the schema in file cve_schema_x.x.x.json.


