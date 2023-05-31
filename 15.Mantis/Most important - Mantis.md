## Tecnicas utilizadas
- Database Enumeration (DBeaver)  
- Bloodhound Enumeration (bloodhound-python)  
- Exploiting MS14-068 (goldenPac.py) [Microsoft Kerberos Checksum Validation Vulnerability]
## Procedimiento
- Fuzzing
- Credentials leak
- Intentar un ASRPRoast attack para un TGT
- Intentar un kerboroasting attack para un TGS
- Bloodhount emnumeration ``bloodhound-python -c ALL -u 'james' -p 'J@m3s_P@ssW0rd!' -ns 10.10.10.52 -d htb.local``
- MS14-068 Exploiting ``goldenPac.py htb.local/james@mantis``


