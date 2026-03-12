# Qilin Ransomware

## Overview

Qilin is a ransomware operation targeting enterprise environments including Windows and virtualized infrastructures.

The group uses a ransomware-as-a-service model and is known for performing data exfiltration before encrypting victim systems.

## Operational Characteristics

Qilin operators perform several stages before deploying ransomware:

- Discovery of accounts
- Privilege escalation
- Token manipulation
- Data encryption

These activities enable the attackers to gain full control over enterprise systems.

## Observed MITRE ATT&CK Techniques

| Technique | Name |
|-----------|------|
T1087.001 | Account Discovery |
T1078 | Valid Accounts |
T1548.002 | Bypass User Account Control |
T1134 | Access Token Manipulation |
T1486 | Data Encrypted for Impact |

## References

MITRE ATT&CK  
https://attack.mitre.org/

CISA Ransomware Resources  
https://www.cisa.gov/ransomware