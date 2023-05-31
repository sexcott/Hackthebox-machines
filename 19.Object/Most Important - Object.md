## Tecnicas utilizadas 
- Jenkins Exploitation (New Job + Abusing Build Periodically) 
- Jenkins Exploitation (Abusing Trigger builds remotely using TOKEN) 
- Firewall Enumeration Techniques Jenkins Password Decrypt 
- BloodHound Enumeration 
- Abusing ForceChangePassword with PowerView Abusing GenericWrite (Set-DomainObject - Setting Script Logon Path) 
- Abusing WriteOwner (Takeover Domain Admins Group) Active Directory
## Procedimiento
- Virtual Hosting
- Crear un proyecto
- Ejecucion remota de comandos con la API de jenkings
- Enumerar reglas de firewall ``Get-NetFirewallRule -Direction Outbound -Action Block -Enable True``
-  Enumerar reglas de firewall permitidas ``Get-NetFirewallRule -Direction Outbound -Action Allow -Enable True``(*filtrar por ICMP*)
- Filtrar por puertos abiertos y cerrados; Buscar en How to display firewall rule ports numbers with powershell
- Listar jenkings
- Jenkings Credentials Decrypt para decriptar.
- Connect to winRM
- Tirar de sharphound.ps1 ``Import-Module .\SharpHound.ps1`` para analizar con bloodhound
- instalar Powerview del repo *PowerSploit* para poder cambiar la contraseña
- Aprovecharse de la cualidad de Smith para cambiar los atributos de Maria(*GenericWrite*) 
- Abusar de la propiedad de maria para introducirnos como Domain Admin(*Abusing WriteOwner*)
![[Pasted image 20221110135042.png]]
![[Pasted image 20221110135122.png]]
