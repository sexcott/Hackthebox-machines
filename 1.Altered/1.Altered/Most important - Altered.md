## Tecnicas utilizadas
-   Brute Force Pin / Rate-Limit Bypass [Headers]
-   Type Juggling Bypassing
-   SQL Injection (Error Based)
-   SQLI to RCE -> INTO OUTFILE Query
-   Dirty Pipe Exploit (But with PAM-Wordle configured)
## Procedimiento
- Brute force with Wfuzz utilizando un payload de tipo range.
- Rate Limit bypass in Hacktricks web
![[Pasted image 20230106114833.png]]
- Type juggling. Cambiar el metodo por el que se envian los datos, de *GET* a *POST*. Cambiamos los datos para que la comparacion del secreto se haga para un dato booleano(**true**) y nos permita asi ejecutar una inyeccion SQL en el campo de *id*.
- Subimos un archivo a la ruta donde se encuentra montado el servidor web con la funcion *into outfile* que tiene Mysql
- Explotamos el dirty piped.
