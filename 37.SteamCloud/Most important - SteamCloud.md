## Tecnicas utilizadas
- Kubernetes API Enumeration (kubectl) 
- Kubelet API Enumeration (kubeletctl) 
- Command Execution through kubeletctl on the containers Cluster Authentication (ca.crt/token files) with kubectl Creating YAML file for PODcreation Executing commands on the new POD Reverse Shell through YAML file while deploying the POD
## Procedimiento
- Utilizar **kubectl** para enumerar kubernete
- Se nos es imposible enumerar con **kubectl**, asi que tiramos por **kubeletctl** para enumerar por los nodos
- Ejecutar una bash con **Kubeletctl**
- Listar por el token y por el ca.crt para poder listar en **kubectl**
- Enumerar las cosas que tenemos realizar en el **kubectl** 
- obtener el contenedor nginx en formato yaml
![[Pasted image 20221103002603.png]]
![[Pasted image 20221103003000.png]]
- Con el pods nuevo creado, podemos conectarnos a el y tendremos la raiz de la maquina victima en una montura.
