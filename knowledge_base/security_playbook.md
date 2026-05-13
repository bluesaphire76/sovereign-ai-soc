# Security Playbook Base

## SSH brute force
Indicatori:
- molteplici login falliti
- invalid user
- failed password
- tentativi da IP esterni

Azioni consigliate:
- verificare login riusciti dopo i fallimenti
- bloccare IP sorgente se confermato malevolo
- disabilitare root login via SSH
- abilitare MFA dove possibile
- applicare rate limiting o fail2ban
- controllare utenti privilegiati

MITRE ATT&CK:
- T1110 Brute Force
- T1078 Valid Accounts

## Privilege escalation via sudo
Indicatori:
- uso anomalo di sudo
- comandi eseguiti come root
- escalation dopo login sospetto

Azioni consigliate:
- verificare utente
- controllare comandi eseguiti
- revisionare sudoers
- controllare sessioni recenti
- validare attività con owner del sistema

MITRE ATT&CK:
- T1548 Abuse Elevation Control Mechanism

