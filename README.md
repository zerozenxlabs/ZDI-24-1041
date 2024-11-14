# CVE-2023-7261
Google Chrome Updater DosDevices Local Privilege Escalation Vulnerability

# Details:

This vulnerability allows local attackers to escalate privileges on affected installations of Google Chrome. 
An attacker must first obtain the ability to execute low-privileged code on the target system in order to exploit this vulnerability.


The specific flaw exists within the update mechanism. By creating a DOS device redirection, an attacker can abuse the update mechanism to launch an executable from an untrusted location. 
An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of SYSTEM.

# References:

- https://issues.chromium.org/issues/40064602
- https://zerozenx.com/
