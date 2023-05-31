## Tenicas utilizadas
- Information Leakage (GitBucket) 
- Breaking Parser Logic - Abusing Reverse Proxy / URI Normalization Exploiting Tomcat -(RCE) [Creating malicious WAR]
- Abusing existing YML Playbook file [Cron Job] 
- Ansible-playbook exploitation (sudo privilege)
## Procedimiento
- Virtual hosting
- Proxy reverse: tomcat
- Default credentials failed!
- Create a new account from GitBucket and see the commits
- Aplicar la tecnica de blathat del 2018 para eludir el reverse proxy
- Autenticarnos al tomcat
- Crear un WAR con **Msfvenom** con el payload *java/jsp_shell_reverse_tcp*
- Upload malicius app and open that
- Aprovecharnos de la tarea cron para crear un enlace simbolico del directorio del usuario
- Explotamos Ansible-playbook tomando como plantilla el archivo .yml que nos ayudo a escalar anteriormente

