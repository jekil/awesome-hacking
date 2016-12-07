=================
 Awesome Hacking
=================

Awesome hacking is an awesome collection of **hacking tools**. Its goal is to collect,
classify and make awesome tools easy to find by humans, creating a **toolset** you can
checkout with one command.

.. contents:: Table of Contents
.. section-numbering::
    :depth: 1

Code Auditing
=============

Static Analysis
---------------

- `Brakeman <http://brakemanscanner.org>`_ - A static analysis security vulnerability scanner for Ruby on Rails applications.

Cryptography
============

- `Xortool <https://github.com/hellman/xortool>`_ - A tool to analyze multi-byte xor cipher.

CTF Tools
=========

- `Pwntools <https://github.com/Gallopsled/pwntools>`_ - CTF framework and exploit development library.

Docker
======

- `Docker Bench for Security <https://hub.docker.com/r/diogomonica/docker-bench-security/>`_ - The Docker Bench for Security checks for all the automatable tests in the CIS Docker 1.6 Benchmark.

    docker pull diogomonica/docker-bench-security

- `DVWA <https://hub.docker.com/r/citizenstig/dvwa/>`_ - Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable.

    docker pull citizenstig/dvwa

- `Kali Linux <https://hub.docker.com/r/kalilinux/kali-linux-docker/>`_ - This Kali Linux Docker image provides a minimal base install of the latest version of the Kali Linux Rolling Distribution.

    docker pull kalilinux/kali-linux-docker 

- `OWASP Mutillidae II <https://hub.docker.com/r/citizenstig/nowasp/>`_ - OWASP Mutillidae II Web Pen-Test Practice Application.

    docker pull citizenstig/nowasp

- `OWASP Railsgoat <https://hub.docker.com/r/owasp/railsgoat/>`_ - A vulnerable version of Rails that follows the OWASP Top 10.

    docker pull owasp/railsgoat

- `OWASP Security Shepherd <https://hub.docker.com/r/ismisepaul/securityshepherd/>`_ - A web and mobile application security training platform.

    docker pull ismisepaul/securityshepherd

- `OWASP WebGoat <https://hub.docker.com/r/danmx/docker-owasp-webgoat/>`_ - A deliberately insecure Web Application.

    docker pull danmx/docker-owasp-webgoat

- `OWASP ZAP <https://hub.docker.com/r/owasp/zap2docker-stable/>`_ - Current stable owasp zed attack proxy release in embedded docker container.

    docker pull owasp/zap2docker-stable

- `Security Ninjas <https://hub.docker.com/r/opendns/security-ninjas/>`_ - An Open Source Application Security Training Program.

    docker pull opendns/security-ninjas

- `Vulnerability as a service: Heartbleed <https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/>`_ - Vulnerability as a Service: CVE 2014-0160.

    docker pull hmlio/vaas-cve-2014-0160

- `Vulnerability as a service: Shellshock <https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/>`_ - Vulnerability as a Service: CVE 2014-6271.

    docker pull hmlio/vaas-cve-2014-6271

- `WPScan <https://hub.docker.com/r/wpscanteam/wpscan/>`_ - WPScan is a black box WordPress vulnerability scanner.

    docker pull wpscanteam/wpscan

Forensics
=========

File Forensics
--------------

- `Autospy <http://www.sleuthkit.org/autopsy/>`_ - A digital forensics platform and graphical interface to The Sleuth Kit and other digital forensics tools.
- `DFF <http://www.digital-forensic.org>`_ - A Forensics Framework coming with command line and graphical interfaces. DFF can be used to investigate hard drives and volatile memory and create reports about user and system activities.
- `Hadoop_framework <https://github.com/sleuthkit/hadoop_framework>`_ - A prototype system that uses Hadoop to process hard drive images.
- `Scalpel <https://github.com/sleuthkit/scalpel>`_ - An open source data carving tool.
- `Sleuthkit <https://github.com/sleuthkit/sleuthkit>`_ - A library and collection of command line digital forensics tools.

Network Forensics
-----------------

- `Dshell <https://github.com/USArmyResearchLab/Dshell>`_ - A network forensic analysis framework.
- `Passivedns <https://github.com/gamelinux/passivedns>`_ - A network sniffer that logs all DNS server replies for use in a passive DNS setup.

Misc
----

- `HxD <https://mh-nexus.de/en/hxd/>`_ - A hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size.

Library
=======

Python
------

- `Scapy <http://www.secdev.org/projects/scapy/>`_ - A python-based interactive packet manipulation program & library.

Live CD - Distributions
=======================

- `ArchStrike <https://archstrike.org>`_ - An Arch Linux repository for security professionals and enthusiasts.
- `BackBox <https://backbox.org>`_ - Ubuntu-based distribution for penetration tests and security assessments.
- `BlackArch <https://www.blackarch.org>`__ - Arch Linux-based distribution for penetration testers and security researchers.
- `BOSSLive <https://bosslinux.in>`_ - An Indian GNU/Linux distribution developed by CDAC and is customized to suit Indian's digital environment. It supports most of the Indian languages.
- `DEFT Linux <http://www.deftlinux.net>`_ - Suite dedicated to incident response and digital forensics.
- `Fedora Security Lab <https://labs.fedoraproject.org/en/security/>`__ - A safe test environment to work on security auditing, forensics, system rescue and teaching security testing methodologies in universities and other organizations.
- `Kali <https://www.kali.org>`_ - A Linux distribution designed for digital forensics and penetration testing.
- `NST <http://networksecuritytoolkit.org>`_ - Network Security Toolkit distribution.
- `Ophcrack <http://ophcrack.sourceforge.net>`_ - A free Windows password cracker based on rainbow tables. It is a very efficient implementation of rainbow tables done by the inventors of the method. It comes with a Graphical User Interface and runs on multiple platforms.
- `Parrot <https://www.parrotsec.org>`_ - Security GNU/Linux distribution designed with cloud pentesting and IoT security in mind.
- `Pentoo <http://www.pentoo.ch>`_ - Security-focused livecd based on Gentoo.
- `REMnux <https://remnux.org>`_ - Toolkit for assisting malware analysts with reverse-engineering malicious software. 

Malware
=======

Dynamic Analysis
----------------

- `Androguard <https://github.com/androguard/androguard/>`_ - Reverse engineering, Malware and goodware analysis of Android applications.

Intelligence
------------

- `Passivedns-client <https://github.com/chrislee35/passivedns-client>`_ - Provides a library and a query tool for querying several passive DNS providers.

Ops
---

- `FakeNet-NG <https://github.com/fireeye/flare-fakenet-ng>`_ - A next generation dynamic network analysis tool for malware analysts and penetration testers. It is open source and designed for the latest versions of Windows.
- `Malboxes <https://github.com/GoSecure/malboxes>`_ - Builds malware analysis Windows VMs so that you don't have to.

Static Analysis
---------------

- `Floss <https://github.com/fireeye/flare-floss>`_ - FireEye Labs Obfuscated String Solver. Automatically extract obfuscated strings from malware.
- `PEview <http://wjradburn.com/software/>`_ - A quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files.
- `Sysinternals Suite <https://technet.microsoft.com/en-us/sysinternals/bb842062>`_ - The Sysinternals Troubleshooting Utilities.

Network
=======

Fake Services
-------------

- `DNSChef <http://thesprawl.org/projects/dnschef/>`_ - DNS proxy for Penetration Testers and Malware Analysts.
- `DnsRedir <https://github.com/iSECPartners/dnsRedir>`_ - A small DNS server that will respond to certain queries with addresses provided on the command line.

Packet Manipulation
-------------------

- `Pig <https://github.com/rafael-santiago/pig>`_ - A Linux packet crafting tool.

Sniffer
-------

- `Dripcap <https://dripcap.org/>`_ - Caffeinated Packet Analyzer.
- `Dsniff <https://www.monkey.org/~dugsong/dsniff/>`_ - A collection of tools for network auditing and pentesting.
- `Moloch <https://github.com/aol/moloch>`_ - Moloch is a open source large scale full PCAP capturing, indexing and database system.
- `NetworkMiner <http://www.netresec.com/?page=NetworkMiner>`_ - A Network Forensic Analysis Tool (NFAT).
- `Netsniff-ng <http://netsniff-ng.org>`_ - A Swiss army knife for your daily Linux network plumbing.
- `OpenFPC <http://www.openfpc.org>`_ - OpenFPC is a set of scripts that combine to provide a lightweight full-packet network traffic recorder and buffering tool. Its design goal is to allow non-expert users to deploy a distributed network traffic recorder on COTS hardware while integrating into existing alert and log tools.
- `PF_RING <http://www.ntop.org/products/packet-capture/pf_ring/>`_ - PF_RING™ is a Linux kernel module and user-space framework that allows you to process packets at high-rates while providing you a consistent API for packet processing applications.
- `Wireshark <https://www.wireshark.org>`_ - A free and open-source packet analyzer.

Penetration Testing
===================

Exploiting
----------

- `BeEF <http://beefproject.com>`_ - The Browser Exploitation Framework Project.
- `Fathomless <https://github.com/xor-function/fathomless>`_ - A collection of different programs for network red teaming.
- `Metasploit Framework <http://www.metasploit.com/>`_ - Exploitation framework.
- `Shellsploit <https://github.com/b3mb4m/shellsploit-framework>`_ - Let's you generate customized shellcodes, backdoors, injectors for various operating system. And let's you obfuscation every byte via encoders.
- `SPARTA <http://sparta.secforce.com>`_ - Network Infrastructure Penetration Testing Tool.
- `Zarp <https://github.com/hatRiot/zarp>`_ - Network Attack Tool.

Exploits
--------

- `The Exploit Database <https://github.com/offensive-security/exploit-database>`_ - The official Exploit Database repository.

Info Gathering
--------------

- `Dnsenum <https://github.com/fwaeytens/dnsenum/>`_ - A perl script that enumerates DNS information.
- `Dnsmap <https://github.com/makefu/dnsmap/>`_ - Passive DNS network mapper.
- `Dnsrecon <https://github.com/darkoperator/dnsrecon/>`_ - DNS Enumeration Script.
- `SMBMap <https://github.com/ShawnDEvans/smbmap>`_ - A handy SMB enumeration tool.
- `SSLMap <http://thesprawl.org/projects/sslmap/>`_ - TLS/SSL cipher suite scanner.

Fuzzing
-------

- `Fuzzbox <https://github.com/iSECPartners/fuzzbox>`_ - A multi-codec media fuzzing tool.
- `Netzob <https://github.com/netzob/netzob>`_ - Netzob is an opensource tool for reverse engineering, traffic generation and fuzzing of communication protocols.
- `Zulu <https://github.com/nccgroup/Zulu.git>`_ - A fuzzer designed for rapid prototyping that normally happens on a client engagement where something needs to be fuzzed within tight timescales.

Mobile
------

- `Idb <http://www.idbtool.com>`_ - A tool to simplify some common tasks for iOS pentesting and research.
- `Introspy-iOS <http://isecpartners.github.io/Introspy-iOS/>`_ - Security profiling for blackbox iOS.

MITM
----

- `Mitmproxy <https://mitmproxy.org/>`_ - An interactive, SSL-capable man-in-the-middle proxy for HTTP with a console interface.
- `Mitmsocks4j <https://github.com/Akdeniz/mitmsocks4j>`_ - Man in the Middle SOCKS Proxy for JAVA.

Password Cracking
-----------------

- `HashCat <https://hashcat.net/hashcat/>`_ - World's fastest and most advanced password recovery utility.
- `Hob0Rules <https://github.com/praetorian-inc/Hob0Rules>`_ - Password cracking rules for Hashcat based on statistics and industry patterns.
- `John the Ripper <http://www.openwall.com/john/>`_ - A fast password cracker.

Port Scanning
-------------

- `Masscan <https://github.com/robertdavidgraham/masscan>`_ - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.

Post Exploitation
-----------------

- `DET <https://github.com/sensepost/DET>`_ - (extensible) Data Exfiltration Toolkit (DET).
- `Fireaway <https://github.com/tcstool/Fireaway>`_ - Next Generation Firewall Audit and Bypass Tool.
- `Mallory <https://github.com/justmao945/mallory>`_ - HTTP/HTTPS proxy over SSH.
- `Mimikatz <http://blog.gentilkiwi.com/mimikatz>`_ - A little tool to play with Windows security.
- `Pwnat <https://samy.pl/pwnat/>`_ - Punches holes in firewalls and NATs allowing any numbers of clients behind NATs to directly connect to a server behind a different NAT.
- `Tgcd <http://tgcd.sourceforge.net>`_ - A simple Unix network utility to extend the accessibility of TCP/IP based network services beyond firewalls.
- `WCE <http://www.ampliasecurity.com/research/windows-credentials-editor/>`_ - Windows Credentials Editor (WCE) is a security tool to list logon sessions and add, change, list and delete associated credentials.

Services
--------

- `Sslstrip <https://moxie.org/software/sslstrip/>`_ - A demonstration of the HTTPS stripping attacks.
- `Sslstrip2 <https://github.com/LeonardoNve/sslstrip2>`_ - SSLStrip version to defeat HSTS.
- `SSLyze <https://github.com/nabla-c0d3/sslyze>`_ - SSL configuration scanner.
- `Tls_prober <https://github.com/WestpointLtd/tls_prober.git>`_ - Fingerprint a server's SSL/TLS implementation.

Training
--------

- `DVWA <http://dvwa.co.uk>`_ - Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable.
- `OWASP Railsgoat <http://railsgoat.cktricky.com/>`_ - A vulnerable version of Rails that follows the OWASP Top 10.
- `OWASP Security Shepherd <https://www.owasp.org/index.php/OWASP_Security_Shepherd>`_ - A web and mobile application security training platform.
- `OWASP WebGoat <https://www.owasp.org/index.php/Category:OWASP_WebGoat_Project>`_ - A deliberately insecure Web Application.
- `RopeyTasks <https://github.com/continuumsecurity/RopeyTasks>`_ - Deliberately vulnerable web application.

Web
---

- `Arachni <http://www.arachni-scanner.com>`_ - Web Application Security Scanner Framework.
- `BlindElephant <http://blindelephant.sourceforge.net>`_ - Web Application Fingerprinter.
- `Cms-explorer <https://code.google.com/archive/p/cms-explorer/>`_ - CMS Explorer is designed to reveal the the specific modules, plugins, components and themes that various CMS driven web sites are running.
- `Dvcs-ripper <https://github.com/kost/dvcs-ripper>`_ - Rip web accessible (distributed) version control systems.
- `Fimap <https://tha-imax.de/git/root/fimap>`_ - Find, prepare, audit, exploit and even google automatically for LFI/RFI bugs.
- `Joomscan <https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project>`_ - Joomla CMS scanner.
- `Kadabra <https://github.com/D35m0nd142/Kadabra>`_ - Automatic LFI Exploiter and Scanner, written in C++ and a couple extern module in Python.
- `Kadimus <https://github.com/P0cL4bs/Kadimus>`_ - LFI scan and exploit tool.
- `Liffy <https://github.com/hvqzao/liffy>`_ - LFI exploitation tool.
- `Nikto2 <https://cirt.net/nikto2>`_ - Web application vulnerability scanner.
- `NoSQLMap <http://www.nosqlmap.net>`_ - Automated Mongo database and NoSQL web application exploitation tool.
- `Paros <https://sourceforge.net/projects/paros/>`_ - A Java based HTTP/HTTPS proxy for assessing web application vulnerability.
- `SQLMap <http://sqlmap.org>`_ - Automatic SQL injection and database takeover tool.
- `TPLMap <https://github.com/epinna/tplmap>`_ - Automatic Server-Side Template Injection Detection and Exploitation Tool.
- `W3af <http://w3af.org>`_ - Web application attack and audit framework.
- `Wapiti <http://wapiti.sourceforge.net>`_ - Web application vulnerability scanner.
- `Weevely3 <https://github.com/epinna/weevely3>`_ - Weaponized web shell.
- `WhatWeb <https://www.morningstarsecurity.com/research/whatweb>`_ - Website Fingerprinter.
- `WPScan <https://wpscan.org>`_ - WPScan is a black box WordPress vulnerability scanner.
- `Zed Attack Proxy (ZAP) <https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project>`_ - The OWASP ZAP core project.

Wireless
--------

- `Aircrack-ng <http://www.aircrack-ng.org>`_ - An 802.11 WEP and WPA-PSK keys cracking program.
- `Kismet <https://kismetwireless.net/>`_ - Wireless network detector, sniffer, and IDS.
- `Reaver <https://code.google.com/archive/p/reaver-wps>`_ - Brute force attack against Wifi Protected Setup.
- `Wifite <https://github.com/derv82/wifite>`_ - Automated wireless attack tool.
- `Wifiphisher <https://github.com/sophron/wifiphisher>`_ - Automated phishing attacks against Wi-Fi networks.

Security
========

Endpoint Security
-----------------

- `Duckhunt <https://github.com/pmsosa/duckhunt>`_ - Prevent RubberDucky (or other keystroke injection) attacks.

Reverse Engineering
===================

- `BinText <http://www.mcafee.com/kr/downloads/free-tools/bintext.aspx>`_ - A small, very fast and powerful text extractor.
- `Bytecode_graph <https://github.com/fireeye/flare-bytecode_graph>`_ - Module designed to modify Python bytecode. Allows instructions to be added or removed from a Python bytecode string.
- `Coda <https://github.com/npamnani/coda>`_ - Coredump analyzer.
- `Edb <http://www.codef00.com/projects#debugger>`_ - A cross platform x86/x86-64 debugger.
- `Dex2jar <https://github.com/pxb1988/dex2jar>`_ - Tools to work with android .dex and java .class files.
- `DotPeek <https://www.jetbrains.com/decompiler/>`_ - A free-of-charge .NET decompiler from JetBrains.
- `Flare-ida <https://github.com/fireeye/flare-ida>`_ - IDA Pro utilities from FLARE team.
- `Hopper <https://www.hopperapp.com>`_ - A OS X and Linux Disassembler/Decompiler for 32/64 bit Windows/Mac/Linux/iOS executables.
- `Idaemu <https://github.com/36hours/idaemu>`_ - Is an IDA Pro Plugin, use for emulating code in IDA Pro.
- `IDA Free <https://www.hex-rays.com/products/ida/support/download_freeware.shtml>`_ - The freeware version of IDA.
- `IDA Pomidor <http://thesprawl.org/projects/ida-pomidor/>`_ - IDA Pomidor is a plugin for Hex-Ray's IDA Pro disassembler that will help you retain concentration and productivity during long reversing sessions.
- `IDA Pro <https://www.hex-rays.com/products/ida/index.shtml>`_ - A Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger.
- `IDA Sploiter <http://thesprawl.org/projects/ida-sploiter/>`_ - IDA Sploiter is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's capabilities as an exploit development and vulnerability research tool.
- `Immunity Debugger <http://debugger.immunityinc.com/>`_ - A powerful new way to write exploits and analyze malware.
- `JAD <http://varaneckas.com/jad/>`_ - JAD Java Decompiler.
- `JD-GUI <http://jd.benow.ca>`_ - Aims to develop tools in order to decompile and analyze Java 5 “byte code” and the later versions.
- `Medusa <https://github.com/wisk/medusa>`_ - A disassembler designed to be both modular and interactive.
- `OllyDbg <http://www.ollydbg.de>`_ - An x86 debugger that emphasizes binary code analysis.
- `PEDA <https://github.com/longld/peda>`_ - Python Exploit Development Assistance for GDB.
- `Plasma <https://github.com/joelpx/plasma>`_ - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code.
- `Radare2 <http://www.radare.org>`_ - Opensource, crossplatform reverse engineering framework.
- `Toolbag <https://github.com/aaronportnoy/toolbag>`_ - The IDA Toolbag is a plugin providing supplemental functionality to Hex-Rays IDA Pro disassembler.
- `Voltron <https://github.com/snare/voltron>`_ - An extensible debugger UI toolkit written in Python. It aims to improve the user experience of various debuggers (LLDB, GDB, VDB and WinDbg) by enabling the attachment of utility views that can retrieve and display data from the debugger host.
- `WinDbg <https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit>`_ - Windows Driver Kit and WinDbg.
- `WinHex <http://www.winhex.com/winhex/>`_ - A hexadecimal editor, helpful in the realm of computer forensics, data recovery, low-level data processing, and IT security.
- `Unlinker <https://github.com/jonwil/unlinker>`_ - Unlinker is a tool that can rip functions out of Visual C++ compiled binaries and produce Visual C++ COFF object files.
- `UPX <https://upx.github.io>`_ - The Ultimate Packer for eXecutables.
- `X64_dbg <http://x64dbg.com>`_ - An open-source x64/x32 debugger for windows.

Social Engineering
==================

Phishing
--------

- `Whatsapp-phishing <https://github.com/Mawalu/whatsapp-phishing>`_ -  Proof of principle code for running a phishing attack against the official Whatsapp Web client.


--------------
 Contributing
--------------

Every kind of contribution is really appreciated! Feature requests, suggestions,
fixes or documentation contributions are welcome.
Please send a patch with your contribution using Github `pull requests <https://help.github.com/articles/using-pull-requests/#sending-the-pull-request>`_ or
just get in touch with me.

----------
 Feedback
----------

Please send questions, comments, suggestions or rants to alessandro@tanasi.it (`@jekil <https://twitter.com/jekil>`_).
