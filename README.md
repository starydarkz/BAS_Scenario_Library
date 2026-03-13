# Ransomware APT Adversary Simulation

This repository contains Cyber Threat Intelligence (CTI) documentation and adversary emulation scenarios based on three ransomware operations:

* DragonForce
* Qilin
* Warlock

The repository includes:

• Threat actor description  
• MITRE ATT\&CK TTP mapping  
• Attack scenario simulation  
• References from CTI sources  
• Importable adversary profiles for MITRE Caldera

These adversaries can be used for:

* Breach \& Attack Simulation
* SOC detection testing
* Security control validation





\# Atomic Update Script

\## Ejecución completa

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera



\## Solo Windows, modo dry-run primero

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera --platforms windows --dry-run



\## Solo técnicas específicas, verbose

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera --tactics T1059 T1003 T1082 --verbose



\## Si ya tienes ART descargado

python3 caldera\_atomic\_sync.py --caldera-path \~/caldera --skip-clone --temp-dir /opt/atomic-red-team

