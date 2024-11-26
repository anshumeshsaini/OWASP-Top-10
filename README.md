OWASP 4.0 Test Guide - Report 
Anshumesh Saini

-

1. Introduction  
OWASP Testing Guide 4.0 is a security guide that provides best practices and testing techniques for securing web applications. Helps identify vulnerabilities and bugs in applications. This ensures protection against potential threats from attackers. Testing every web application is important to protect it from malicious vulnerabilities.  


2. Weak points of injection  
An injection vulnerability occurs when an attacker modifies an application's input fields to inject malicious code into the system. The most common type is SQL Injection.

![image1](https://github.com/user-attachments/assets/8d948f5c-eb41-46ff-9fd5-81fd39af3f65)

example:
If the search box on your website is at risk An attacker can enter information such as `"1 OR 1=1"` to gain unauthorized access to, for example, an admin page.  

Protection:
- Always sanitize user input.  
- Use parameterized queries to secure database interactions.  



3. Broken Authentication  
Broken authentication occurs when a weak system allows attackers to hijack user accounts.


example: ![Broken Authentication](https://github.com/user-attachments/assets/760cf253-c0c3-4ab8-b575-a6c03f4c034b)

If a user sets a simple password such as `"1234"`, an attacker can easily use a brute-force attack to gain access to the account.  

Protection:
- Enforce a strong password policy (e.g., at least 8 characters including special characters).  
- Uses multi-factor authentication (MFA) to improve security.  


4. Disclosure of sensitive information  
Sensitive information such as passwords, credit card details or personal information They may be exposed if they are not properly encrypted during storage or transmission.  

example:
If sensitive data is sent without encryption Attackers using web sniffing tools can intercept and steal data.  


Protection: ![Prevent Sensituve data](https://github.com/user-attachments/assets/d0d905c6-c1aa-4fb8-ad82-b7c775a29529)
- Always use HTTPS  
- Encrypt data during storage and transmission
  

5. XML External Entities (XXE)  
An XXE attack occurs when an attacker sends a malicious XML file to an outside organization that has access to sensitive server data.  

example:
If your server processes an XML file and an attacker sends a malicious XML file. Servers may also expose sensitive server files.  
![XML](https://github.com/user-attachments/assets/3236f1c8-a3ac-4262-8daf-a445bea4759a)


Protection:
- Disable external entities in XML processing.  
- Uses a secure XML parser that blocks malicious payloads
  

 6. Broken access controls  
This vulnerability occurs when a user accesses restricted resources without permission. As a result, the security of the system is reduced.  

example:![Broken Access control](https://github.com/user-attachments/assets/86c9ddf7-3f17-4b3a-a239-6fa5e4aa2b09)

If a normal user can access the administration page directly by typing the URL, then access control isn't working.  

Protection:
- Use role-based access control (RBAC) to assign permissions based on user roles.  
- Ensure that access verification is enforced on the server side.
  


 7. Incorrect security configuration  
Insecure settings can lead to incorrect security configurations, such as enabling default credentials or redundant services.  

example:
If your server uses default credentials such as `"admin/administrator"`, an attacker can gain easy access.

Prevention:
- Change default credentials.  
- Harden server configurations and disable unnecessary services.  



 8. Cross-site scripting (XSS)  
An XSS attack occurs when a malicious script is injected into a website and executed in the user's browser.  

example: ![XSS](https://github.com/user-attachments/assets/722f3f62-26ea-45e8-9cca-81c197e4b3fd)

If user input is not cleaned Attackers can inject JavaScript code to hijack a user's session or redirect to a malicious site.  

Protection: 
- Sanitize user input  
- Use output encryption to securely handle user input.  


9. Insecure recording  
The vulnerability occurs during deserialization of untrusted data. This allows attackers to inject malicious code.  

example:  
If your application directly decrypts user data Attackers can deliver malicious payloads for remote code execution.  

Protection:
- Avoid sorting unreliable data.  
- If necessary, validate input data before deserializing.

10. Use of components with known weaknesses.  
Outdated software or libraries that contain known vulnerabilities can be exploited by attackers.  

example: 
If your application uses older libraries, such as jQuery or old versions of Apache Struts, attackers can exploit its vulnerabilities.  

Protection:
- Update libraries and dependencies regularly.  
- Use automatic vulnerability scanning tools to detect outdated components  


11. Server-side request-forgery (SSRF)  

SSRF attacks force the server to send requests to unauthorized internal or external resources.  

example:![SSRF](https://github.com/user-attachments/assets/6e763114-f484-4ecb-b4e1-dce92e8fc0c6)
Attackers can manipulate your server to send requests to their own malicious servers. by revealing sensitive server information  

Protection: 
- Verify input URL  
- Restrict access to internal resources from external requests  

12. Conclusion  
The OWASP Testing Guide is an essential resource for securing web applications. By testing applications regularly and following security best practices. You can protect your applications from potential threats and ensure that user data remains safe.

 
 13. References  
1. **OWASP Testing Guide 4.0**  
   *Link:* [OWASP Testing Guide 4.0]  
2. **OWASP Top Ten 2021**  
   *Link:* [OWASP Top Ten 2021]  
3. **OWASP Web Security Testing Guide (WSTG)**  
   *Link:* [OWASP WSTG]  
4. **OWASP Cheat Sheet Series**  
   *Link:* [OWASP Cheat Sheets]  
5. **OWASP Dependency-Check**  
