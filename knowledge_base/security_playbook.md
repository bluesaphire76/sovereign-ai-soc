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

## Suspicious PowerShell execution
Indicatori:
- PowerShell con parametri encodedcommand o bypass
- download di script da URL esterni
- esecuzione da percorsi temporanei o profili utente
- child process anomali da Office, browser o interpreti script

Azioni consigliate:
- recuperare command line completa e parent process
- verificare hash e percorso dello script
- controllare connessioni di rete vicine all'esecuzione
- validare se l'attivita e stata pianificata da amministratori
- isolare l'host solo dopo conferma analyst e impatto business

MITRE ATT&CK:
- T1059.001 PowerShell
- T1105 Ingress Tool Transfer

## Wazuh agent stopped or disconnected
Indicatori:
- agent disconnected o stopped
- assenza improvvisa di eventi da host critico
- service restart non pianificato
- heartbeat worker o source freshness degradati

Azioni consigliate:
- verificare stato del servizio Wazuh agent sull'host
- controllare manutenzioni pianificate o reboot
- confrontare ultimo evento, ultimo heartbeat e finestra di ingest
- validare con owner del sistema prima di trattarlo come evasione
- aprire follow-up se l'host resta cieco oltre la soglia operativa

MITRE ATT&CK:
- T1562 Impair Defenses

## DNS beaconing or suspicious domain lookup
Indicatori:
- query DNS ripetute verso domini rari o appena osservati
- pattern periodico con intervalli regolari
- domini con entropia elevata o sottodomini lunghi
- query vicine a un alert host o network

Azioni consigliate:
- verificare top domains, client IP e host associato
- correlare con Suricata flow, HTTP o TLS nello stesso intervallo
- controllare se il dominio appartiene a servizi aziendali noti
- non inferire causalita senza evidenza di connessione o payload
- conservare dominio, client IP e finestra temporale nel case

MITRE ATT&CK:
- T1071.004 DNS

## Suricata high severity IDS alert
Indicatori:
- alert Suricata ad alta severita
- signature associata a exploit, C2 o malware
- flussi ripetuti tra stesso host e destinazione
- match temporale con Wazuh, DNS o incidente correlato

Azioni consigliate:
- leggere signature, category, src/dst IP, porta e protocollo
- verificare se ci sono eventi Wazuh sullo stesso host
- distinguere alert IDS da prova di compromissione
- cercare flow, TLS SNI, HTTP host e DNS query correlate
- escalare solo se piu sorgenti supportano la stessa ipotesi

MITRE ATT&CK:
- T1041 Exfiltration Over C2 Channel
- T1071 Application Layer Protocol

## Suspicious package or software installation
Indicatori:
- installazione pacchetti fuori finestra manutentiva
- nuovi binari in percorsi non standard
- package manager eseguito da account inatteso
- installazione vicina a escalation sudo o login sospetto

Azioni consigliate:
- identificare pacchetto, versione, repository e utente
- verificare ticket, change request o attivita amministrativa
- controllare processi avviati dopo l'installazione
- confrontare hash e path con baseline aziendale
- se non autorizzato, pianificare containment con approvazione

MITRE ATT&CK:
- T1105 Ingress Tool Transfer
- T1547 Boot or Logon Autostart Execution

## Multiple failed logins followed by success
Indicatori:
- molteplici fallimenti di autenticazione
- login riuscito dallo stesso utente, host o IP dopo i fallimenti
- source IP esterno o non usuale
- accesso seguito da sudo, shell interattiva o modifica file

Azioni consigliate:
- verificare successful login dopo la sequenza di fallimenti
- controllare geolocalizzazione, ASN e reputazione IP
- confrontare con storico utente e orario normale di lavoro
- controllare comandi, sessioni e processi successivi al login
- richiedere reset credenziali o MFA step-up se confermato rischio

MITRE ATT&CK:
- T1110 Brute Force
- T1078 Valid Accounts
