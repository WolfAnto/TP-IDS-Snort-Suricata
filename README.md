# TP-IDS-Snort-Suricata
...
Voici le plan d’adressage :
Internet 192.168.2.0/23 ( RT )
DMZ 192.168.4.0/24
Réseau interne 192.168.5.0/24


VM 1 :
nano /etc/network/interfaces
auto eth0
auto eth1
auto br0
iface br0 inet manual
		bridge-interfaces eth1 eth0

VM 2 :
nano /etc/network/interfaces
auto eth0
iface eth0 inet static
address 192.168.5.1/24


Vérifier le trafic (VM 1) :
```
tcpdump -nvx -i eth0
iptables -t nat -F 
iptables -A OUTPUT -o eth1 -j DROP
apt-get install iptables-persistent 
iptables-save > /etc/iptables/rules
```

```
apt install suricata
apt install suricata-oinkmaster-updater
apt install suricata-update
```

```
nano /etc/suricata/rules/my.rules
```

```
alert icmp any any -> any any (msg:"test icmp";)
alert ip any any -> any any (msg:"root attack"; content:"uid=0|28|root|29|"; ) 
```

```
nano /etc/suricata/suricata.yaml
```
[...]
```
default-rule-path: /etc/suricata/rules
rule-files:
 - my.rules
 - botcc.rules
```

```
/etc/init.d/suricata restart
```

```
ping 192.168.2.5
```
dans une autre console : 
```
tail -f /var/log/suricata/fast.log 
```

Tester les règles suivantes :
1. Log des connexions FTP :
```
alert tcp any any -> any 21 (msg:"Connexion FTP détectée"; flow:established,to_server; content:"USER"; pcre:"/^USER\s[^rR].*/smi"; classtype:policy-violation; sid:1000001; rev:1;)
```

2. Alert d'une tentative de connexion avec USER root :
```
 tcp any any -> any 21 (msg:"Tentative de connexion avec USER root"; flow:established,to_server; content:"USER"; content:"root"; distance:0; classtype:attempted-admin; sid:1000002; rev:1;)
```

3. Alert de connexion HTTP vers Internet avec les mots sex, adults :
```
alert tcp any any -> any 80 (msg:"Mots interdits dans la requête HTTP"; flow:established,to_server; content:"GET"; http_uri; pcre:"/sex|adults/i"; classtype:policy-violation; sid:1000003; rev:1;)
```

4. Alert de connexions de l'Internet vers la base MySQL :
```
alert tcp any any -> any 3306 (msg:"Connexion entrante vers MySQL"; flow:established,to_server; content:"J"; offset:4; depth:1; classtype:attempted-recon; sid:1000004; rev:1;)
```

5. Alert d'un trafic Kazaa :
```
alert tcp any any -> any any (msg:"Trafic Kazaa détecté"; flow:established; content:"UserAgent\: KazaaClient"; classtype:policy-violation; sid:1000005; rev:1;)
```

```
wget https://download.splunk.com/products/splunk/releases/8.1.3/linux/splunk-8.1.3-
63079c59e632-linux-2.6-amd64.deb
```

```
dpkg -i splunk-8.1.3-63079c59e632-linux-2.6-amd64.deb
```

```
cd /opt/splunk/bin
```

```
./splunk start
```

IHM de gestion : 
```
http://127.0.0.1:8000
```

Paramètres → entrées de données → fichier ajouter /var/log/suricata/eve.json
