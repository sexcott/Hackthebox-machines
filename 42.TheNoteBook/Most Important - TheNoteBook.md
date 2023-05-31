## Tecnicas utilizadas
- Abusing JWT (Gaining privileges)  
- Abusing Upload File  
- Docker Breakout [CVE-2019-5736 - RUNC] (Privilege Escalation)
## Procedimiento
- probar Brute force con wfuzz para emnumerar usuarios, y probar romper la password.
- Hacer uso de la pagina **jwt.io** para decodear la cookie de sesión que pinta ser Json por los **Puntos** que contiene.
- Generar una key con openssl ``openssl genrsa -out $nameKey $bites ``
- Generar la nueva cookie y pegarla para acceder como admin.
- Aprovecharse de que la web interpreta archivos PHP para entablar una reverse shell
- User pivoting con el backup(id_rsa)
- CVE de docker para la version utilizada ''