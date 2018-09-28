=================
 Awesome Hacking
=================

Awesome hacking is a curated list of **hacking tools** for hackers, pentesters and security researchers.
Its goal is to collect, classify and make awesome tools easy to find by humans, creating a **toolset** you can
checkout and update with one command.

You can checkout all the tools with the following command::

    git clone --recursive https://github.com/jekil/awesome-hacking.git

Every kind of **contribution** is really appreciated! Follow the :doc:`contribute`.

*If you enjoy this work, please keep it alive contributing or just sharing it!* - `@jekil <https://twitter.com/jekil>`_

.. contents:: Table of Contents
   :depth: 2
   :backlinks: entry

Code Auditing
=============

Static Analysis
---------------

- `Brakeman <http://brakemanscanner.org>`_ - A static analysis security vulnerability scanner for Ruby on Rails applications.
- `ShellCheck <https://github.com/koalaman/shellcheck>`_ - A static analysis tool for shell scripts.

Cryptography
============

- `FeatherDuster <https://github.com/nccgroup/featherduster>`_ - An automated, modular cryptanalysis tool.
- `RSATool <https://github.com/ius/rsatool>`_ - Generate private key with knowledge of p and q.
- `Xortool <https://github.com/hellman/xortool>`_ - A tool to analyze multi-byte xor cipher.

CTF Tools
=========

- `CTFd <https://ctfd.io>`_ - CTF in a can. Easily modifiable and has everything you need to run a jeopardy style CTF.
- `FBCTF <https://github.com/facebook/fbctf>`_ - Platform to host Capture the Flag competitions.
- `Mellivora <https://github.com/Nakiami/mellivora>`_ - A CTF engine written in PHP.
- `OneGadget <https://github.com/david942j/one_gadget>`_ - A tool for you easy to find the one gadget RCE in libc.so.6.
- `NightShade <https://github.com/UnrealAkama/NightShade>`_ - A simple security CTF framework.
- `OpenCTF <https://github.com/easyctf/openctf>`_ - CTF in a box. Minimal setup required.
- `Pwntools <https://github.com/Gallopsled/pwntools>`_ - CTF framework and exploit development library.
- `Scorebot <https://github.com/legitbs/scorebot>`_ - Platform for CTFs by Legitbs (Defcon).
- `V0lt <https://github.com/P1kachu/v0lt>`_ - Security CTF Toolkit.

Docker
======

- `Docker Bench for Security <https://hub.docker.com/r/diogomonica/docker-bench-security/>`_ - The Docker Bench for Security checks for all the automatable tests in the CIS Docker 1.6 Benchmark.

    docker pull diogomonica/docker-bench-security

- `DVWA <https://hub.docker.com/r/citizenstig/dvwa/>`_ - Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable.

    docker pull citizenstig/dvwa

- `Kali Linux <https://hub.docker.com/r/kalilinux/kali-linux-docker/>`_ - This Kali Linux Docker image provides a minimal base install of the latest version of the Kali Linux Rolling Distribution.

    docker pull kalilinux/kali-linux-docker 

- `Metasploit <https://hub.docker.com/r/remnux/metasploit/>`_ - Metasploit Framework penetration testing software (unofficial docker).

   docker pull remnux/metasploit

- `OWASP Juice Shop <https://hub.docker.com/r/bkimminich/juice-shop/>`_ - An intentionally insecure webapp for security trainings written entirely in Javascript which encompasses the entire OWASP Top Ten and other severe security flaws.

    docker pull bkimminich/juice-shop

- `OWASP Mutillidae II <https://hub.docker.com/r/citizenstig/nowasp/>`_ - OWASP Mutillidae II Web Pen-Test Practice Application.

    docker pull citizenstig/nowasp

- `OWASP NodeGoat <https://github.com/owasp/nodegoat#option-3>`_ - An environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.

    git clone https://github.com/OWASP/NodeGoat.git
    docker-compose build && docker-compose up

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

- `SpamScope <https://hub.docker.com/r/fmantuano/spamscope-elasticsearch/>`_ - SpamScope (Fast Advanced Spam Analysis Tool) Elasticsearch.

    docker pull fmantuano/spamscope-elasticsearch

- `Vulnerable WordPress Installation <https://hub.docker.com/r/wpscanteam/vulnerablewordpress/>`_ - Vulnerable WordPress Installation.

    docker pull wpscanteam/vulnerablewordpress

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

- `Autopsy <http://www.sleuthkit.org/autopsy/>`_ - A digital forensics platform and graphical interface to The Sleuth Kit and other digital forensics tools.
- `DFF <http://www.digital-forensic.org>`_ - A Forensics Framework coming with command line and graphical interfaces. DFF can be used to investigate hard drives and volatile memory and create reports about user and system activities.
- `Docker Explorer <https://github.com/google/docker-explorer>`_ - A tool to help forensicate offline docker acquisitions.
- `Hadoop_framework <https://github.com/sleuthkit/hadoop_framework>`_ - A prototype system that uses Hadoop to process hard drive images.
- `OSXCollector <http://yelp.github.io/osxcollector/>`_ - A forensic evidence collection & analysis toolkit for OS X.
- `Scalpel <https://github.com/sleuthkit/scalpel>`_ - An open source data carving tool.
- `Shellbags <https://github.com/williballenthin/shellbags>`_ - Investigate NT_USER.dat files.
- `Sleuthkit <https://github.com/sleuthkit/sleuthkit>`_ - A library and collection of command line digital forensics tools.

Incident Response
-----------------

- `Hunter <https://github.com/ThreatHuntingProject/hunter>`_ - A threat hunting / data analysis environment based on Python, Pandas, PySpark and Jupyter Notebook.

Live Analysis
-------------

- `OS X Auditor <OS X Auditor is a free Mac OS X computer forensics tool>`_ - OS X Auditor is a free Mac OS X computer forensics tool.
- `Windows-event-forwarding <https://github.com/palantir/windows-event-forwarding>`_ - A repository for using windows event forwarding for incident detection and response.

Memory Forensics
----------------

- `Rekall <http://www.rekall-forensic.com>`_ - Memory analysis framework developed by Google.
- `Volatility <http://www.volatilityfoundation.org>`_ - Extract digital artifacts from volatile memory (RAM) samples.

Mobile
------

- `Android Forensic Toolkit <https://code.google.com/archive/p/aft/>`_ - Allows you to extract SMS records, call history, photos, browsing history, and password from an Android phone.
- `Mem <https://github.com/MobileForensicsResearch/mem>`_ - Tool used for dumping memory from Android devices.

Network Forensics
-----------------

- `Dshell <https://github.com/USArmyResearchLab/Dshell>`_ - A network forensic analysis framework.
- `Dnslog <https://github.com/stamparm/dnslog>`_ - Minimalistic DNS logging tool.
- `Passivedns <https://github.com/gamelinux/passivedns>`_ - A network sniffer that logs all DNS server replies for use in a passive DNS setup.

Misc
----

- `Diffy <https://github.com/Netflix-Skunkworks/diffy>`_ - A digital forensics and incident response (DFIR) tool developed by Netflix's Security Intelligence and Response Team (SIRT). Allows a forensic investigator to quickly scope a compromise across cloud instances during an incident, and triage those instances for followup actions.
- `HxD <https://mh-nexus.de/en/hxd/>`_ - A hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size.
- `Libfvde <https://github.com/libyal/libfvde>` - Library and tools to access FileVault Drive Encryption (FVDE) encrypted volumes.

Intelligence
============

- `Attackintel <https://github.com/gr4ym4ntx/attackintel>`_ - A python script to query the MITRE ATT&CK API for tactics, techniques, mitigations, & detection methods for specific threat groups.
- `VIA4CVE <https://github.com/cve-search/VIA4CVE>`_ - An aggregator of the known vendor vulnerabilities database to support the expansion of information with CVEs.

Library
=======

C
-

- `Libdnet <https://github.com/dugsong/libdnet>`_ - Provides a simplified, portable interface to several low-level networking routines, including network address manipulation, kernel arp cache and route table lookup and manipulation, network firewalling, network interface lookup and manipulation, IP tunnelling, and raw IP packet and Ethernet frame transmission.

Java
----

- `Libsignal-service-java <https://github.com/whispersystems/libsignal-service-java/>`_ - A Java/Android library for communicating with the Signal messaging service.

Python
------

- `Amodem <https://github.com/romanz/amodem>`_ - Audio MODEM Communication Library in Python.
- `Dpkt <https://github.com/kbandla/dpkt>`_ - Fast, simple packet creation / parsing, with definitions for the basic TCP/IP protocols.
- `Pcapy <https://www.coresecurity.com/corelabs-research/open-source-tools/pcapy>`_ - A Python extension module that interfaces with the libpcap packet capture library. Pcapy enables python scripts to capture packets on the network. Pcapy is highly effective when used in conjunction with a packet-handling package such as Impacket, which is a collection of Python classes for constructing and dissecting network packets.
- `PyBFD <https://github.com/Groundworkstech/pybfd/>`_ - Python interface to the GNU Binary File Descriptor (BFD) library.
- `Pynids <https://jon.oberheide.org/pynids/>`_ - A python wrapper for libnids, a Network Intrusion Detection System library offering sniffing, IP defragmentation, TCP stream reassembly and TCP port scan detection. Let your own python routines examine network conversations.
- `Pypcap <https://github.com/dugsong/pypcap>`_ - This is a simplified object-oriented Python wrapper for libpcap.
- `PyPDF2 <http://mstamy2.github.io/PyPDF2>`_ - A utility to read and write PDFs with Python.
- `Python-ptrace <https://github.com/haypo/python-ptrace>`_ - Python binding of ptrace library.
- `RDPY <https://github.com/citronneur/rdpy>`_ - RDPY is a pure Python implementation of the Microsoft RDP (Remote Desktop Protocol) protocol (client and server side).
- `Scapy <http://www.secdev.org/projects/scapy/>`_ - A python-based interactive packet manipulation program & library.

Ruby
----

- `Secureheaders <https://github.com/twitter/secureheaders>`_ - Security related headers all in one gem.

Live CD - Distributions
=======================

- `Android Tamer <https://androidtamer.com>`_ - Virtual / Live Platform for Android Security professionals.
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
- `Cuckoo Sandbox <http://www.cuckoosandbox.org>`_ - An automated dynamic malware analysis system.
- `CuckooDroid <https://github.com/idanr1986/cuckoo-droid>`_ - Automated Android Malware Analysis with Cuckoo Sandbox.
- `DECAF <https://github.com/sycurelab/DECAF>`_ - Short for Dynamic Executable Code Analysis Framework, is a binary analysis platform based on QEMU.
- `DroidBox <https://github.com/pjlantz/droidbox>`_ - Dynamic analysis of Android apps.
- `Hooker <https://github.com/AndroidHooker/hooker>`_ - An opensource project for dynamic analyses of Android applications.
- `Jsunpack-n <https://github.com/urule99/jsunpack-n>`_ - Emulates browser functionality when visiting a URL.
- `Magento-malware-scanner <https://github.com/gwillem/magento-malware-scanner>`_ - A collection of rules and samples to detect Magento malware.
- `Malzilla <http://malzilla.sourceforge.net>`_ - Web pages that contain exploits often use a series of redirects and obfuscated code to make it more difficult for somebody to follow. MalZilla is a useful program for use in exploring malicious pages. It allows you to choose your own user agent and referrer, and has the ability to use proxies. It shows you the full source of webpages and all the HTTP headers. It gives you various decoders to try and deobfuscate javascript aswell.
- `ProbeDroid <https://github.com/ZSShen/ProbeDroid>`_ - A dynamic binary instrumentation kit targeting on Android(Lollipop) 5.0 and above.
- `PyEMU <https://code.google.com/archive/p/pyemu/>`_ - Fully scriptable IA-32 emulator, useful for malware analysis.
- `Uitkyk <https://github.com/brompwnie/uitkyk>`_ - Runtime memory analysis framework to identify Android malware.
- `WScript Emulator <https://github.com/mrpapercut/wscript/>`_ - Emulator/tracer of the Windows Script Host functionality.

Honeypot
--------

- `Basic-auth-pot <https://github.com/bjeborn/basic-auth-pot>`_ - HTTP Basic Authentication honeyPot.
- `Conpot <https://github.com/mushorg/conpot>`_ - ICS/SCADA honeypot.
- `Cowrie <https://github.com/micheloosterhof/cowrie>`_ - SSH honeypot, based on Kippo.
- `Elastichoney <https://github.com/jordan-wright/elastichoney>`_ - A Simple Elasticsearch Honeypot.
- `ESPot <https://github.com/mycert/ESPot>`_ - An Elasticsearch honeypot written in NodeJS, to capture every attempts to exploit CVE-2014-3120.
- `Delilah <https://github.com/Novetta/delilah>`_ - An Elasticsearch Honeypot written in Python.
- `Dionaea <https://github.com/DinoTools/dionaea>`_ - Honeypot designed to trap malware.
- `Glastopf <https://github.com/mushorg/glastopf>`_ - Web Application Honeypot.
- `Glutton <https://github.com/mushorg/glutton>`_ - All eating honeypot.
- `Honeyd <http://www.honeyd.org>`_ - Create a virtual honeynet.
- `HoneyPress <https://github.com/dustyfresh/HoneyPress>`_ - python based WordPress honeypot in a docker container.
- `HonnyPotter <https://github.com/MartinIngesen/HonnyPotter>`_ - A WordPress login honeypot for collection and analysis of failed login attempts.
- `Maildb <https://github.com/kevthehermit/Maildb>`_ - Python Web App to Parse and Track Email and http Pcap Files.
- `MHN <https://github.com/threatstream/mhn>`_ - Multi-snort and honeypot sensor management, uses a network of VMs, small footprint SNORT installations, stealthy dionaeas, and a centralized server for management.
- `Mnemosyne <https://github.com/johnnykv/mnemosyne>`_ - A normalizer for honeypot data; supports Dionaea.
- `MongoDB-HoneyProxy <https://github.com/Plazmaz/MongoDB-HoneyProxy>`_ - A honeypot proxy for mongodb. When run, this will proxy and log all traffic to a dummy mongodb server.
- `MysqlPot <https://github.com/schmalle/MysqlPot>`_ - A mysql honeypot, still very very early stage.
- `Nodepot <https://github.com/schmalle/Nodepot>`_ - A nodejs web application honeypot.
- `NoSQLPot <https://github.com/torque59/nosqlpot>`_ - The NoSQL Honeypot Framework.
- `Phoneyc <https://github.com/buffer/phoneyc>`_ - Pure Python honeyclient implementation.
- `Phpmyadmin_honeypot <https://github.com/gfoss/phpmyadmin_honeypot>`_ - A simple and effective phpMyAdmin honeypot.
- `Servletpot <https://github.com/schmalle/servletpot>`_ - Web application Honeypot.
- `Shadow Daemon <https://shadowd.zecure.org>`_ - A modular Web Application Firewall / High-Interaction Honeypot for PHP, Perl & Python apps.
- `Smart-honeypot <https://github.com/freak3dot/smart-honeypot>`_ - PHP Script demonstrating a smart honey pot.
- `SpamScope <https://github.com/SpamScope/spamscope>`_ - Fast Advanced Spam Analysis Tool.
- `Thug <https://github.com/buffer/thug>`_ - Low interaction honeyclient, for investigating malicious websites.
- `Wordpot <https://github.com/gbrindisi/wordpot>`_ - A WordPress Honeypot.
- `Wp-smart-honeypot <https://github.com/freak3dot/wp-smart-honeypot>`_ - WordPress plugin to reduce comment spam with a smarter honeypot.

Intelligence
------------

- `MISP Modules <https://github.com/MISP/misp-modules>`_ - Modules for expansion services, import and export in MISP.
- `Passivedns-client <https://github.com/chrislee35/passivedns-client>`_ - Provides a library and a query tool for querying several passive DNS providers.
- `Rt2jira <https://github.com/fireeye/rt2jira>`_ - Convert RT tickets to JIRA tickets.

Ops
---

- `Al-khaser <https://github.com/LordNoteworthy/al-khaser>`_ - Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.
- `CapTipper <https://github.com/omriher/CapTipper>`_ - A python tool to analyze, explore and revive HTTP malicious traffic.
- `CSCGuard <https://github.com/glinares/CSCGuard>`_ - Protects and logs suspicious and malicious usage of .NET CSC.exe and Runtime C# Compilation.
- `Google-play-crawler <https://github.com/Akdeniz/google-play-crawler>`_ - Google-play-crawler is simply Java tool for searching android applications on GooglePlay, and also downloading them.
- `Googleplay-api <https://github.com/egirault/googleplay-api>`_ - An unofficial Python API that let you search, browse and download Android apps from Google Play (formerly Android Market).
- `ImaginaryC2 <https://github.com/felixweyne/imaginaryC2>`_ - A python tool which aims to help in the behavioral (network) analysis of malware. Imaginary C2 hosts a HTTP server which captures HTTP requests towards selectively chosen domains/IPs. Additionally, the tool aims to make it easy to replay captured Command-and-Control responses/served payloads.
- `FakeNet-NG <https://github.com/fireeye/flare-fakenet-ng>`_ - A next generation dynamic network analysis tool for malware analysts and penetration testers. It is open source and designed for the latest versions of Windows.
- `Malboxes <https://github.com/GoSecure/malboxes>`_ - Builds malware analysis Windows VMs so that you don't have to.
- `Mquery <https://github.com/CERT-Polska/mquery>`_ - YARA malware query accelerator (web frontend).
- `Node-appland <https://github.com/dweinstein/node-appland>`_ - NodeJS tool to download APKs from appland.
- `Node-aptoide <https://github.com/dweinstein/node-aptoide>`_ - NodeJS to download APKs from aptoide.
- `Node-google-play <https://github.com/dweinstein/node-google-play>`_ - Call Google Play APIs from Node.

Source Code
-----------

- `Android-malware <https://github.com/ashishb/android-malware>`_ - Collection of android malware samples.
- `Carberp <https://github.com/hzeroo/Carberp>`_ - Carberp leaked source code.
- `Fancybear <https://github.com/rickey-g/fancybear>`_ - Fancy Bear Source Code.
- `Mirai <https://github.com/jgamblin/Mirai-Source-Code>`_ - Leaked Mirai Source Code for Research/IoC Development Purposes.
- `Morris Worm <https://github.com/arialdomartini/morris-worm>`_ - The original Morris Worm source code.
- `TinyNuke <https://github.com/rossja/TinyNuke>`_ - Zeus-style banking trojan.
- `Zeus <https://github.com/Visgean/Zeus>`_ - Zeus version 2.0.8.9, leaked in 2011.

Static Analysis
---------------

- `Androwarn <https://github.com/maaaaz/androwarn/>`_ - Detect and warn the user about potential malicious behaviours developped by an Android application.
- `ApkAnalyser <https://github.com/sonyxperiadev/ApkAnalyser>`_ - A static, virtual analysis tool for examining and validating the development work of your Android app.
- `APKinspector <https://github.com/honeynet/apkinspector/>`_ A powerful GUI tool for analysts to analyze the Android applications.
- `Argus-SAF <http://pag.arguslab.org/argus-saf>`_ - Argus static analysis framework.
- `CFGScanDroid <https://github.com/douggard/CFGScanDroid>`_ - Control Flow Graph Scanning for Android.
- `ConDroid <https://github.com/JulianSchuette/ConDroid>`_ - Symbolic/concolic execution of Android apps.
- `DroidLegacy <https://bitbucket.org/srl/droidlegacy>`_ - Static analysis scripts.
- `Floss <https://github.com/fireeye/flare-floss>`_ - FireEye Labs Obfuscated String Solver. Automatically extract obfuscated strings from malware.
- `FSquaDRA <https://github.com/zyrikby/FSquaDRA>`_ - Fast detection of repackaged Android applications based on the comparison of resource files included into the package.
- `Inspeckage <https://github.com/ac-pm/Inspeckage>`_ - Android Package Inspector - dynamic analysis with api hooks, start unexported activities and more.
- `Maldrolyzer <https://github.com/maldroid/maldrolyzer>`_ - Simple framework to extract "actionable" data from Android malware (C&Cs, phone numbers, etc).
- `Peepdf <http://eternal-todo.com/tools/peepdf-pdf-analysis-tool>`_ - A Python tool to explore PDF files in order to find out if the file can be harmful or not. The aim of this tool is to provide all the necessary components that a security researcher could need in a PDF analysis without using 3 or 4 tools to make all the tasks.
- `PEfile <https://github.com/erocarrera/pefile>`_ - Read and work with Portable Executable (aka PE) files.
- `PEview <http://wjradburn.com/software/>`_ - A quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files.
- `Pdfminer <https://euske.github.io/pdfminer/>`_ - A tool for extracting information from PDF documents.
- `PScout <http://pscout.csl.toronto.edu>`_ - Analyzing the Android Permission Specification.
- `Smali-CFGs <https://github.com/EugenioDelfa/Smali-CFGs>`_ - Smali Control Flow Graph's.
- `SmaliSCA <https://github.com/dorneanu/smalisca>`_ - Smali Static Code Analysis.
- `Sysinternals Suite <https://technet.microsoft.com/en-us/sysinternals/bb842062>`_ - The Sysinternals Troubleshooting Utilities.
- `Yara <http://virustotal.github.io/yara/>`_ - Identify and classify malware samples.

Network
=======

Analysis
--------

- `Bro <http://www.bro.org>`_ - A powerful network analysis framework that is much different from the typical IDS you may know.
- `Pytbull <http://pytbull.sourceforge.net>`_ - A python based flexible IDS/IPS testing framework.
- `Sguil <http://bammv.github.io/sguil/index.html>`_ - Sguil (pronounced sgweel) is built by network security analysts for network security analysts. Sguil's main component is an intuitive GUI that provides access to realtime events, session data, and raw packet captures.

Fake Services
-------------

- `DNSChef <http://thesprawl.org/projects/dnschef/>`_ - DNS proxy for Penetration Testers and Malware Analysts.
- `DnsRedir <https://github.com/iSECPartners/dnsRedir>`_ - A small DNS server that will respond to certain queries with addresses provided on the command line.

Packet Manipulation
-------------------

- `Pig <https://github.com/rafael-santiago/pig>`_ - A Linux packet crafting tool.
- `Yersinia <http://www.yersinia.net>`_ - A network tool designed to take advantage of some weakeness in different network protocols. It pretends to be a solid framework for analyzing and testing the deployed networks and systems.

Sniffer
-------

- `Cloud-pcap <https://github.com/thepacketgeek/cloud-pcap>`_ - Web PCAP storage and analytics.
- `Dnscap <https://www.dns-oarc.net/tools/dnscap>`_ - Network capture utility designed specifically for DNS traffic.
- `Dripcap <https://dripcap.org/>`_ - Caffeinated Packet Analyzer.
- `Dsniff <https://www.monkey.org/~dugsong/dsniff/>`_ - A collection of tools for network auditing and pentesting.
- `Justniffer <http://justniffer.sourceforge.net/>`_ - Just A Network TCP Packet Sniffer. Justniffer is a network protocol analyzer that captures network traffic and produces logs in a customized way, can emulate Apache web server log files, track response times and extract all "intercepted" files from the HTTP traffic.
- `Moloch <https://github.com/aol/moloch>`_ - Moloch is a open source large scale full PCAP capturing, indexing and database system.
- `Net-creds <https://github.com/DanMcInerney/net-creds>`_ - Sniffs sensitive data from interface or pcap.
- `NetworkMiner <http://www.netresec.com/?page=NetworkMiner>`_ - A Network Forensic Analysis Tool (NFAT).
- `Netsniff-ng <http://netsniff-ng.org>`_ - A Swiss army knife for your daily Linux network plumbing.
- `OpenFPC <http://www.openfpc.org>`_ - OpenFPC is a set of scripts that combine to provide a lightweight full-packet network traffic recorder and buffering tool. Its design goal is to allow non-expert users to deploy a distributed network traffic recorder on COTS hardware while integrating into existing alert and log tools.
- `PF_RING <http://www.ntop.org/products/packet-capture/pf_ring/>`_ - PF_RING™ is a Linux kernel module and user-space framework that allows you to process packets at high-rates while providing you a consistent API for packet processing applications.
- `WebPcap <https://github.com/sparrowprince/WebPcap>`_ - A web-based packet analyzer (client/server architecture). Useful for analyzing distributed applications or embedded devices.
- `Wireshark <https://www.wireshark.org>`_ - A free and open-source packet analyzer.

Penetration Testing
===================

DoS
---

- `DHCPig <https://github.com/kamorin/DHCPig>`_ - DHCP exhaustion script written in python using scapy network library.
- `LOIC <https://github.com/NewEraCracker/LOIC/>`_ - Low Orbit Ion Cannon - An open source network stress tool, written in C#. Based on Praetox's LOIC project.
- `Sockstress <https://github.com/defuse/sockstress>`_ - Sockstress (TCP DoS) implementation.
- `T50 <http://t50.sf.net/>`_ - The more fast network stress tool.
- `Torshammer <https://github.com/dotfighter/torshammer>`_ - Tor's hammer. Slow post DDOS tool written in python.
- `UFONet <http://ufonet.03c8.net>`_ - Abuses OSI Layer 7-HTTP to create/manage 'zombies' and to conduct different attacks using; GET/POST, multithreading, proxies, origin spoofing methods, cache evasion techniques, etc.

Exploiting
----------

- `BeEF <http://beefproject.com>`_ - The Browser Exploitation Framework Project.
- `Commix <http://www.commixproject.com>`_ - Automated All-in-One OS Command Injection and Exploitation Tool.
- `DLLInjector <https://github.com/OpenSecurityResearch/dllinjector>`_ - Inject dlls in processes.
- `Drupwn <https://github.com/immunIT/drupwn>`_ - Drupal enumeration & exploitation tool.
- `ExploitPack <http://exploitpack.com>`_ - Graphical tool for penetration testing with a bunch of exploits.
- `Evilgrade <https://github.com/infobyte/evilgrade>`_ - The update explotation framework.
- `Fathomless <https://github.com/xor-function/fathomless>`_ - A collection of different programs for network red teaming.
- `Linux Exploit Suggester <https://github.com/PenturaLabs/Linux_Exploit_Suggester>`_ - Linux Exploit Suggester; based on operating system release number.
- `Metasploit Framework <http://www.metasploit.com/>`_ - Exploitation framework.
- `Nessus <http://www.tenable.com/products/nessus-vulnerability-scanner>`_ - Vulnerability, configuration, and compliance assessment.
- `Nexpose <https://www.rapid7.com/products/nexpose/>`_ - Vulnerability Management & Risk Management Software.
- `OpenVAS <http://www.openvas.org>`_ - Open Source vulnerability scanner and manager.
- `PowerSploit <https://github.com/PowerShellMafia/PowerSploit/>`_ - A PowerShell Post-Exploitation Framework.
- `PSKernel-Primitives <https://github.com/FuzzySecurity/PSKernel-Primitives>`_ - Exploit primitives for PowerShell.
- `ROP Gadget <http://shell-storm.org/project/ROPgadget/>`_ - Framework for ROP exploitation.
- `Routersploit <https://github.com/reverse-shell/routersploit>`_ - Automated penetration testing software for router.
- `Rupture <https://github.com/dionyziz/rupture/>`_ - A framework for BREACH and other compression-based crypto attacks.
- `Shellen <https://github.com/merrychap/shellen>`_ - Interactive shellcoding environment to easily craft shellcodes.
- `Shellsploit <https://github.com/b3mb4m/shellsploit-framework>`_ - Let's you generate customized shellcodes, backdoors, injectors for various operating system. And let's you obfuscation every byte via encoders.
- `SPARTA <http://sparta.secforce.com>`_ - Network Infrastructure Penetration Testing Tool.
- `Spoodle <https://github.com/vjex/spoodle>`_ - A mass subdomain + poodle vulnerability scanner.
- `Veil Framework <https://www.veil-framework.com>`_ - A tool designed to generate metasploit payloads that bypass common anti-virus solutions.
- `Vuls <https://github.com/future-architect/vuls>`_ - Vulnerability scanner for Linux/FreeBSD, agentless, written in Go.
- `Windows Exploit Suggester <https://github.com/GDSSecurity/Windows-Exploit-Suggester>`_ - Detects potential missing patches on the target.
- `Zarp <https://github.com/hatRiot/zarp>`_ - Network Attack Tool.

Exploits
--------

- `Bluedroid <https://github.com/JiounDai/Bluedroid>`_ - PoCs of Vulnerabilities on Bluedroid.
- `Chakra-2016-11 <https://github.com/theori-io/chakra-2016-11>`_ - Proof-of-Concept exploit for Edge bugs (CVE-2016-7200 & CVE-2016-7201).
- `CVE-2018-8120 <https://github.com/bigric3/cve-2018-8120>`_ - CVE-2018-8120.
- `CVE-2018-8897 <https://github.com/nmulasmajic/CVE-2018-8897>`_ - Implements the POP/MOV SS (CVE-2018-8897) vulnerability by bugchecking the machine (local DoS).
- `HolicPOC <https://github.com/leeqwind/HolicPOC>`_ - CVE-2015-2546, CVE-2016-0165, CVE-2016-0167, CVE-2017-0101, CVE-2017-0263, CVE-2018-8120.
- `Jira-Scan <https://github.com/random-robbie/Jira-Scan>`_ - Jira scanner for CVE-2017-9506.
- `MS17-010 <https://github.com/worawit/MS17-010>`_ - Exploits for MS17-010.
- `Ruby-advisory-db <https://github.com/rubysec/ruby-advisory-db>`_ - A database of vulnerable Ruby Gems.
- `The Exploit Database <https://github.com/offensive-security/exploit-database>`_ - The official Exploit Database repository.
- `XiphosResearch Exploits <https://github.com/XiphosResearch/exploits>`_ - Miscellaneous proof of concept exploit code written at Xiphos Research for testing purposes.

Info Gathering
--------------

- `Bundler-audit <https://github.com/rubysec/bundler-audit>`_ - Patch-level verification for Bundler.
- `Dnsenum <https://github.com/fwaeytens/dnsenum/>`_ - A perl script that enumerates DNS information.
- `Dnsmap <https://github.com/makefu/dnsmap/>`_ - Passive DNS network mapper.
- `Dnsrecon <https://github.com/darkoperator/dnsrecon/>`_ - DNS Enumeration Script.
- `Knock <https://github.com/guelfoweb/knock>`_ - A python tool designed to enumerate subdomains on a target domain through a wordlist.
- `IVRE <https://ivre.rocks>`_ - An open-source framework for network recon. It relies on open-source well-known tools to gather data (network intelligence), stores it in a database, and provides tools to analyze it.
- `Operative-framework <https://github.com/graniet/operative-framework>`_ - This is a framework based on fingerprint action, this tool is used for get information on a website or a enterprise target with multiple modules (Viadeo search,Linkedin search, Reverse email whois, Reverse ip whois, SQL file forensics ...).
- `Recon-ng <https://bitbucket.org/LaNMaSteR53/recon-ng>`_ - A full-featured Web Reconnaissance framework written in Python.
- `SMBMap <https://github.com/ShawnDEvans/smbmap>`_ - A handy SMB enumeration tool.
- `SSLMap <http://thesprawl.org/projects/sslmap/>`_ - TLS/SSL cipher suite scanner.
- `Subbrute <https://github.com/TheRook/subbrute>`_ - A DNS meta-query spider that enumerates DNS records, and subdomains.
- `SubFinder <https://github.com/subfinder/subfinder>`_ - A subdomain discovery tool that discovers valid subdomains for websites. Designed as a passive framework to be useful for bug bounties and safe for penetration testing.
- `TruffleHog <https://github.com/dxa4481/truffleHog>`_ - Searches through git repositories for high entropy strings, digging deep into commit history.
- `URLextractor <https://github.com/eschultze/URLextractor>`_ - Information gathering & website reconnaissance.
- `VHostScan <https://github.com/codingo/VHostScan>`_ - A virtual host scanner that performs reverse lookups, can be used with pivot tools, detect catch-all scenarios, aliases and dynamic default pages.
- `Wmap <https://github.com/MaYaSeVeN/Wmap>`_ - Information gathering for web hacking.
- `XRay <https://github.com/evilsocket/xray>`_ - A tool for recon, mapping and OSINT gathering from public networks.

Fuzzing
-------

- `AndroFuzz <https://github.com/jonmetz/AndroFuzz>`_ - A fuzzing utility for Android that focuses on reporting and delivery portions of the fuzzing process.
- `Construct <http://construct.readthedocs.org>`_ - Declarative data structures for python that allow symmetric parsing and building.
- `Fusil <http://fusil.readthedocs.io/>`_ - A Python library used to write fuzzing programs. It helps to start process with a prepared environment (limit memory, environment variables, redirect stdout, etc.), start network client or server, and create mangled files.
- `Fuzzbox <https://github.com/iSECPartners/fuzzbox>`_ - A multi-codec media fuzzing tool.
- `Fuzzlyn <https://github.com/jakobbotsch/Fuzzlyn>`_ - Fuzzer for the .NET toolchains, utilizes Roslyn to generate random C# programs.
- `Honggfuzz <http://google.github.io/honggfuzz/>`_ - Security oriented fuzzer with powerful analysis options. Supports evolutionary, feedback-driven fuzzing based on code coverage (sw and hw).
- `Melkor-android <https://github.com/anestisb/melkor-android>`_ - An Android port of the melkor ELF fuzzer.
- `MFFA <https://github.com/fuzzing/MFFA>`_ - Media Fuzzing Framework for Android.
- `Netzob <https://github.com/netzob/netzob>`_ - Netzob is an opensource tool for reverse engineering, traffic generation and fuzzing of communication protocols.
- `Python-AFL <http://jwilk.net/software/python-afl>`_ - American fuzzy lop fork server and instrumentation for pure-Python code.
- `Radamsa-android <https://github.com/anestisb/radamsa-android>`_ - An Android port of radamsa fuzzer.
- `SecLists <https://github.com/danielmiessler/SecLists>`_ - A collection of multiple types of lists used during security assessments.
- `Sulley <https://github.com/OpenRCE/sulley>`_ - Fuzzer development and fuzz testing framework consisting of multiple extensible components.
- `TAOF <https://sourceforge.net/projects/taof/>`_ - The Art of Fuzzing, including ProxyFuzz, a man-in-the-middle non-deterministic network fuzzer.
- `Windows IPC Fuzzing Tools <https://www.nccgroup.trust/us/about-us/resources/windows-ipc-fuzzing-tools/>`_ - A collection of tools used to attack applications that use Windows Interprocess Communication mechanisms.
- `Zulu <https://github.com/nccgroup/Zulu.git>`_ - A fuzzer designed for rapid prototyping that normally happens on a client engagement where something needs to be fuzzed within tight timescales.

Mobile
------

- `AFE <https://github.com/appknox/AFE>`_ - Android Framework for Exploitation, is a framework for exploiting android based devices.
- `AndroBugs <https://github.com/AndroBugs/AndroBugs_Framework>`_ - An efficient Android vulnerability scanner that helps developers or hackers find potential security vulnerabilities in Android applications.
- `Android-vts <https://github.com/AndroidVTS/android-vts>`_ - Android Vulnerability Test Suite - In the spirit of open data collection, and with the help of the community, let's take a pulse on the state of Android security.
- `Androl4b <https://github.com/sh4hin/Androl4b>`_ - A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis.
- `CobraDroid <https://thecobraden.com/projects/cobradroid/>`_ - A custom build of the Android operating system geared specifically for application security analysts and for individuals dealing with mobile malware.
- `Drozer <http://mwr.to/drozer>`_ - The Leading Security Assessment Framework for Android.
- `Idb <http://www.idbtool.com>`_ - A tool to simplify some common tasks for iOS pentesting and research.
- `Introspy-iOS <http://isecpartners.github.io/Introspy-iOS/>`_ - Security profiling for blackbox iOS.
- `JAADAS <https://github.com/flankerhqd/JAADAS>`_ - Joint Advanced Defect assEsment for android applications.
- `Mobile Security Framework <http://opensecurity.in>`_ - An intelligent, all-in-one open source mobile application (Android/iOS/Windows) automated pen-testing framework capable of performing static, dynamic analysis and web API testing.
- `QARK <https://github.com/linkedin/qark/>`_ - QARK by LinkedIn is for app developers to scan app for security issues.

MITM
----

- `Dnsspoof <https://github.com/DanMcInerney/dnsspoof>`_ - DNS spoofer. Drops DNS responses from the router and replaces it with the spoofed DNS response.
- `Ettercap <http://www.ettercap-project.org>`_ - A comprehensive suite for man in the middle attacks. It features sniffing of live connections, content filtering on the fly and many other interesting tricks. It supports active and passive dissection of many protocols and includes many features for network and host analysis.
- `Bettercap <https://bettercap.org/>`_ - A powerful, flexible and portable tool created to perform various types of MITM attacks against a network, manipulate HTTP, HTTPS and TCP traffic in realtime, sniff for credentials and much more.
- `Caplets <https://github.com/bettercap/caplets>`_ - Bettercap scripts (caplets) and proxy modules.
- `Mallory <https://bitbucket.org/IntrepidusGroup/mallory>`_ - An extensible TCP/UDP man in the middle proxy that is designed to be run as a gateway. Unlike other tools of its kind, Mallory supports modifying non-standard protocols on the fly.
- `MITMf <https://github.com/byt3bl33d3r/MITMf>`_ - Framework for Man-In-The-Middle attacks.
- `Mitmproxy <https://mitmproxy.org/>`_ - An interactive, SSL-capable man-in-the-middle proxy for HTTP with a console interface.
- `Mitmsocks4j <https://github.com/Akdeniz/mitmsocks4j>`_ - Man in the Middle SOCKS Proxy for JAVA.
- `Nogotofail <https://github.com/google/nogotofail>`_ - An on-path blackbox network traffic security testing tool.
- `Responder <https://github.com/SpiderLabs/Responder>`_ - A LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
- `Ssh-mitm <https://github.com/jtesta/ssh-mitm>`_ - An SSH/SFTP man-in-the-middle tool that logs interactive sessions and passwords.

Password Cracking
-----------------

- `BozoCrack <https://github.com/juuso/BozoCrack>`_ - A silly & effective MD5 cracker in Ruby.
- `Common-substr <https://github.com/SensePost/common-substr>`_ - Simple awk script to extract the most common substrings from an input text. Built for password cracking.
- `HashCat <https://hashcat.net/hashcat/>`_ - World's fastest and most advanced password recovery utility.
- `Hob0Rules <https://github.com/praetorian-inc/Hob0Rules>`_ - Password cracking rules for Hashcat based on statistics and industry patterns.
- `John the Ripper <http://www.openwall.com/john/>`_ - A fast password cracker.
- `THC-Hydra <https://www.thc.org/thc-hydra/>`_ - A very fast network logon cracker which support many different services.

Port Scanning
-------------

- `Angry IP Scanner <http://angryip.org>`_ - Fast and friendly network scanner.
- `Masscan <https://github.com/robertdavidgraham/masscan>`_ - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
- `Nmap <https://nmap.org>`_ - Free Security Scanner For Network Exploration & Security Audits.
- `Watchdog <https://github.com/flipkart-incubator/watchdog>`_ - A Comprehensive Security Scanning and a Vulnerability Management Tool.
- `Zmap <https://zmap.io>`_ - An open-source network scanner that enables researchers to easily perform Internet-wide network studies. 

Post Exploitation
-----------------

- `CrackMapExec <https://github.com/byt3bl33d3r/CrackMapExec>`_ - A post-exploitation tool that helps automate assessing the security of large Active Directory networks.
- `CredCrack <https://github.com/gojhonny/CredCrack>`_ - A fast and stealthy credential harvester.
- `Creddump <https://github.com/moyix/creddump>`_ - Dump windows credentials.
- `DBC2 <https://github.com/Arno0x/DBC2>`_ - DropboxC2 is a modular post-exploitation tool, composed of an agent running on the victim's machine, a controler, running on any machine, powershell modules, and Dropbox servers as a means of communication.
- `DET <https://github.com/sensepost/DET>`_ - (extensible) Data Exfiltration Toolkit (DET).
- `Dnsteal <https://github.com/m57/dnsteal>`_ - DNS Exfiltration tool for stealthily sending files over DNS requests.
- `Empire <http://www.powershellempire.com>`_ - Empire is a pure PowerShell post-exploitation agent.
- `Enumdb <https://github.com/m8r0wn/enumdb>`_ - MySQL and MSSQL brute force and post exploitation tool to search through databases and extract sensitive information.
- `EvilOSX <https://github.com/Marten4n6/EvilOSX>`_ - A pure python, post-exploitation, RAT (Remote Administration Tool) for macOS / OSX.
- `Fireaway <https://github.com/tcstool/Fireaway>`_ - Next Generation Firewall Audit and Bypass Tool.
- `FruityC2 <https://github.com/xtr4nge/FruityC2>`_ - A post-exploitation (and open source) framework based on the deployment of agents on compromised machines. Agents are managed from a web interface under the control of an operator.
- `GetVulnerableGPO <https://github.com/gpoguy/GetVulnerableGPO.git>`_ - PowerShell script to find 'vulnerable' security-related GPOs that should be hardended.
- `Iodine <http://code.kryo.se/iodine>`_ - Lets you tunnel IPv4 data through a DNS server.
- `Koadic <https://github.com/zerosum0x0/koadic>`_ - Koadic C3 COM Command & Control - JScript RAT.
- `Mallory <https://github.com/justmao945/mallory>`_ - HTTP/HTTPS proxy over SSH.
- `Mimikatz <http://blog.gentilkiwi.com/mimikatz>`_ - A little tool to play with Windows security.
- `Mimikittenz <https://github.com/putterpanda/mimikittenz>`_ - A post-exploitation powershell tool for extracting juicy info from memory.
- `P0wnedShell <https://github.com/Cn33liz/p0wnedShell>`_ - PowerShell Runspace Post Exploitation Toolkit.
- `ProcessHider <https://github.com/M00nRise/ProcessHider>`_ - Post-exploitation tool for hiding processes from monitoring applications.
- `PowerOPS <https://github.com/fdiskyou/PowerOPS>`_ - PowerShell Runspace Portable Post Exploitation Tool aimed at making Penetration Testing with PowerShell "easier".
- `Poet <https://github.com/mossberg/poet>`_ - Post-exploitation tool.
- `Pupy <https://github.com/n1nj4sec/pupy>`_ - An opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool mainly written in python.
- `Pwnat <https://samy.pl/pwnat/>`_ - Punches holes in firewalls and NATs allowing any numbers of clients behind NATs to directly connect to a server behind a different NAT.
- `RemoteRecon <https://github.com/xorrior/RemoteRecon>`_ - Remote Recon and Collection.
- `SpYDyishai <https://github.com/Night46/spYDyishai>`_ - A Gmail credential harvester.
- `Tgcd <http://tgcd.sourceforge.net>`_ - A simple Unix network utility to extend the accessibility of TCP/IP based network services beyond firewalls.
- `TheFatRat <https://github.com/Exploit-install/TheFatRat>`_ - An easy tool to generate backdoor with msfvenom (a part from metasploit framework). This tool compiles a malware with popular payload and then the compiled malware can be execute on windows, android, mac . The malware that created with this tool also have an ability to bypass most AV software protection.
- `WCE <http://www.ampliasecurity.com/research/windows-credentials-editor/>`_ - Windows Credentials Editor (WCE) is a security tool to list logon sessions and add, change, list and delete associated credentials.

Reporting
---------

- `Dradis <https://dradisframework.com/ce/>`_ - Colllaboration and reporting for IT Security teams.
- `Faraday <http://www.faradaysec.com>`_ - Collaborative Penetration Test and Vulnerability Management Platform.

Services
--------

- `Sslstrip <https://moxie.org/software/sslstrip/>`_ - A demonstration of the HTTPS stripping attacks.
- `Sslstrip2 <https://github.com/LeonardoNve/sslstrip2>`_ - SSLStrip version to defeat HSTS.
- `SSLyze <https://github.com/nabla-c0d3/sslyze>`_ - SSL configuration scanner.
- `Tls_prober <https://github.com/WestpointLtd/tls_prober.git>`_ - Fingerprint a server's SSL/TLS implementation.

Training
--------

- `Don't Panic <https://github.com/antire-book/dont_panic>`_ - Training linux bind shell with anti-reverse engineering techniques.
- `DVWA <http://dvwa.co.uk>`_ - Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable.
- `DVWS <https://github.com/interference-security/DVWS>`_ - Damn Vulnerable Web Sockets (DVWS) is a vulnerable web application which works on web sockets for client-server communication.
- `OWASP Juice Shop <https://www.owasp.org/index.php/OWASP_Juice_Shop_Project>`_ - An intentionally insecure webapp for security trainings written entirely in Javascript which encompasses the entire OWASP Top Ten and other severe security flaws.
- `OWASP NodeGoat <https://www.owasp.org/index.php/Projects/OWASP_Node_js_Goat_Project>`_ - An environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
- `OWASP Railsgoat <http://railsgoat.cktricky.com/>`_ - A vulnerable version of Rails that follows the OWASP Top 10.
- `OWASP Security Shepherd <https://www.owasp.org/index.php/OWASP_Security_Shepherd>`_ - A web and mobile application security training platform.
- `OWASP WebGoat <https://www.owasp.org/index.php/Category:OWASP_WebGoat_Project>`_ - A deliberately insecure Web Application.
- `RopeyTasks <https://github.com/continuumsecurity/RopeyTasks>`_ - Deliberately vulnerable web application.

Web
---

- `Arachni <http://www.arachni-scanner.com>`_ - Web Application Security Scanner Framework.
- `BlindElephant <http://blindelephant.sourceforge.net>`_ - Web Application Fingerprinter.
- `Burp Suite <http://portswigger.net/burp/>`_ - An integrated platform for performing security testing of web applications.
- `Cms-explorer <https://code.google.com/archive/p/cms-explorer/>`_ - CMS Explorer is designed to reveal the the specific modules, plugins, components and themes that various CMS driven web sites are running.
- `Dvcs-ripper <https://github.com/kost/dvcs-ripper>`_ - Rip web accessible (distributed) version control systems.
- `Fimap <https://tha-imax.de/git/root/fimap>`_ - Find, prepare, audit, exploit and even google automatically for LFI/RFI bugs.
- `Joomscan <https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project>`_ - Joomla CMS scanner.
- `Kadabra <https://github.com/D35m0nd142/Kadabra>`_ - Automatic LFI Exploiter and Scanner, written in C++ and a couple extern module in Python.
- `Kadimus <https://github.com/P0cL4bs/Kadimus>`_ - LFI scan and exploit tool.
- `Liffy <https://github.com/hvqzao/liffy>`_ - LFI exploitation tool.
- `Netsparker <https://www.netsparker.com>`_ - Web Application Security Scanner.
- `Nikto2 <https://cirt.net/nikto2>`_ - Web application vulnerability scanner.
- `NoSQLMap <http://www.nosqlmap.net>`_ - Automated Mongo database and NoSQL web application exploitation tool.
- `OWASP Xenotix <https://www.owasp.org/index.php/OWASP_Xenotix_XSS_Exploit_Framework>`_ - XSS Exploit Framework is an advanced Cross Site Scripting (XSS) vulnerability detection and exploitation framework.
- `Paros <https://sourceforge.net/projects/paros/>`_ - A Java based HTTP/HTTPS proxy for assessing web application vulnerability.
- `Ratproxy <https://code.google.com/archive/p/ratproxy/>`_ - A semi-automated, largely passive web application security audit tool, optimized for an accurate and sensitive detection, and automatic annotation, of potential problems.
- `Scout2 <https://nccgroup.github.io/Scout2/>`_ - Security auditing tool for AWS environments.
- `Skipfish <https://code.google.com/archive/p/skipfish/>`_ - An active web application security reconnaissance tool. It prepares an interactive sitemap for the targeted site by carrying out a recursive crawl and dictionary-based probes.
- `SQLMap <http://sqlmap.org>`_ - Automatic SQL injection and database takeover tool.
- `SQLNinja <http://sqlninja.sourceforge.net/>`_ - SQL Server injection & takeover tool.
- `TPLMap <https://github.com/epinna/tplmap>`_ - Automatic Server-Side Template Injection Detection and Exploitation Tool.
- `Tracy <https://github.com/nccgroup/tracy>`_ - A tool designed to assist with finding all sinks and sources of a web application and display these results in a digestible manner.
- `Yasuo <https://github.com/0xsauby/yasuo>`_ - A ruby script that scans for vulnerable & exploitable 3rd-party web applications on a network.
- `W3af <http://w3af.org>`_ - Web application attack and audit framework.
- `Wapiti <http://wapiti.sourceforge.net>`_ - Web application vulnerability scanner.
- `Weevely3 <https://github.com/epinna/weevely3>`_ - Weaponized web shell.
- `WhatWeb <https://www.morningstarsecurity.com/research/whatweb>`_ - Website Fingerprinter.
- `Wordpress Exploit Framework <https://github.com/rastating/wordpress-exploit-framework>`_ - A Ruby framework for developing and using modules which aid in the penetration testing of WordPress powered websites and systems.
- `WPScan <https://wpscan.org>`_ - WPScan is a black box WordPress vulnerability scanner.
- `WPSploit <https://github.com/espreto/wpsploit>`_ - Exploiting Wordpress With Metasploit.
- `WS-Attacker <https://github.com/RUB-NDS/WS-Attacker>`_ - A modular framework for web services penetration testing.
- `XSS-payload-list <https://github.com/ismailtasdelen/xss-payload-list>`_- XSS Payload list.
- `Zed Attack Proxy (ZAP) <https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project>`_ - The OWASP ZAP core project.

Wireless
--------

- `Aircrack-ng <http://www.aircrack-ng.org>`_ - An 802.11 WEP and WPA-PSK keys cracking program.
- `Kismet <https://kismetwireless.net/>`_ - Wireless network detector, sniffer, and IDS.
- `Krackattacks-scripts <https://github.com/vanhoefm/krackattacks-scripts>`_ - Scripts to test if clients or access points (APs) are affected by the KRACK attack against WPA2.
- `LANs.py <https://github.com/DanMcInerney/LANs.py>`_ - Inject code, jam wifi, and spy on wifi users.
- `Mass-deauth <http://rfkiller.github.io/mass-deauth/>`_ - A script for 802.11 mass-deauthentication.
- `Reaver <https://code.google.com/archive/p/reaver-wps>`_ - Brute force attack against Wifi Protected Setup.
- `Wifikill <https://github.com/roglew/wifikill>`_ - A python program to kick people off of wifi.
- `Wifijammer <https://github.com/DanMcInerney/wifijammer>`_ - Continuously jam all wifi clients/routers.
- `Wifite <https://github.com/derv82/wifite>`_ - Automated wireless attack tool.
- `Wifiphisher <https://github.com/sophron/wifiphisher>`_ - Automated phishing attacks against Wi-Fi networks.

Security
========

Cloud Security
--------------

- `Azucar <https://github.com/nccgroup/azucar/>`_ - Security auditing tool for Azure environments.

Endpoint Security
-----------------

- `AIDE <http://aide.sourceforge.net>`_ - Advanced Intrusion Detection Environment is a file and directory integrity checker.
- `Duckhunt <https://github.com/pmsosa/duckhunt>`_ - Prevent RubberDucky (or other keystroke injection) attacks.
- `Hardentools <https://github.com/securitywithoutborders/hardentools>`_ - A utility that disables a number of risky Windows features.
- `Lynis <https://github.com/CISOfy/lynis>`_ - Security auditing tool for Linux, macOS, and UNIX-based systems. Assists with compliance testing (HIPAA/ISO27001/PCI DSS) and system hardening. Agentless, and installation optional.
- `Osx-config-check <https://github.com/kristovatlas/osx-config-check>`_ - Verify the configuration of your OS X machine.
- `Xnumon <https://github.com/droe/xnumon>`_ - Monitor macOS for malicious activity.

Privacy
-------

- `GoSecure <https://iadgov.github.io/goSecure/>`_ - An easy to use and portable Virtual Private Network (VPN) system built with Linux and a Raspberry Pi.
- `I2P <https://geti2p.net>`_ - The Invisible Internet Project.
- `Nipe <https://github.com/GouveaHeitor/nipe>`_ - A script to make Tor Network your default gateway.
- `SecureDrop <https://freedom.press/securedrop>`_ - Open-source whistleblower submission system that media organizations can use to securely accept documents from and communicate with anonymous sources.
- `Tor <https://www.torproject.org>`_ - The free software for enabling onion routing online anonymity.

Reverse Engineering
===================

- `AndBug <https://github.com/swdunlop/AndBug>`_ - A debugger targeting the Android platform's Dalvik virtual machine intended for reverse engineers and developers.
- `Angr <https://github.com/angr/angr>`_ - A platform-agnostic binary analysis framework developed by the Computer Security Lab at UC Santa Barbara and their associated CTF team, Shellphish.
- `Apk2Gold <https://github.com/lxdvs/apk2gold>`_ - Yet another Android decompiler.
- `ApkTool <https://ibotpeaches.github.io/Apktool/>`_ - A tool for reverse engineering Android apk files.
- `Barf <https://github.com/programa-stic/barf-project>`_ - Binary Analysis and Reverse engineering Framework.
- `BinText <http://www.mcafee.com/kr/downloads/free-tools/bintext.aspx>`_ - A small, very fast and powerful text extractor.
- `BinWalk <https://github.com/devttys0/binwalk>`_ - Analyze, reverse engineer, and extract firmware images.
- `Boomerang <https://github.com/nemerle/boomerang>`_ - Decompile x86 binaries to C.
- `Bytecode-viewer <https://bytecodeviewer.com>`_ - A Java 8 Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More).
- `Bytecode_graph <https://github.com/fireeye/flare-bytecode_graph>`_ - Module designed to modify Python bytecode. Allows instructions to be added or removed from a Python bytecode string.
- `Capstone <http://www.capstone-engine.org>`_ - Lightweight multi-platform, multi-architecture disassembly framework with Python bindings.
- `CHIPSEC <https://github.com/chipsec/chipsec>`_ - Platform Security Assessment Framework.
- `Coda <https://github.com/npamnani/coda>`_ - Coredump analyzer.
- `Ctf_import <https://github.com/docileninja/ctf_import>`_ – Run basic functions from stripped binaries cross platform.
- `Edb <http://www.codef00.com/projects#debugger>`_ - A cross platform x86/x86-64 debugger.
- `Dex2jar <https://github.com/pxb1988/dex2jar>`_ - Tools to work with android .dex and java .class files.
- `Distorm <https://github.com/gdabah/distorm>`_ - Powerful Disassembler Library For x86/AMD64.
- `DotPeek <https://www.jetbrains.com/decompiler/>`_ - A free-of-charge .NET decompiler from JetBrains.
- `Enjarify <https://github.com/google/enjarify>`_ - A tool for translating Dalvik bytecode to equivalent Java bytecode. This allows Java analysis tools to analyze Android applications.
- `Fibratus <https://github.com/rabbitstack/fibratus>`_ - Tool for exploration and tracing of the Windows kernel.
- `Fino <https://github.com/sysdream/fino>`_ - An Android Dynamic Analysis Tool.
- `Flare-ida <https://github.com/fireeye/flare-ida>`_ - IDA Pro utilities from FLARE team.
- `Frida <https://www.frida.re>`_ - Inject JavaScript to explore native apps on Windows, macOS, Linux, iOS, Android, and QNX.
- `Gdb-dashboard <https://github.com/cyrus-and/gdb-dashboard>`_ - Modular visual interface for GDB in Python.
- `GEF <https://gef.readthedocs.io/en/latest/>`_ - Multi-Architecture GDB Enhanced Features for Exploiters & Reverse-Engineers.
- `Heap-viewer <https://github.com/danigargu/heap-viewer>`_ - An IDA Pro plugin to examine the glibc heap, focused on exploit development.
- `Hopper <https://www.hopperapp.com>`_ - A OS X and Linux Disassembler/Decompiler for 32/64 bit Windows/Mac/Linux/iOS executables.
- `Idaemu <https://github.com/36hours/idaemu>`_ - Is an IDA Pro Plugin, use for emulating code in IDA Pro.
- `IDA Free <https://www.hex-rays.com/products/ida/support/download_freeware.shtml>`_ - The freeware version of IDA.
- `IDA Patcher <https://github.com/iphelix/ida-patcher>`_ - IDA Patcher is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's ability to patch binary files and memory.
- `IDA Pomidor <http://thesprawl.org/projects/ida-pomidor/>`_ - IDA Pomidor is a plugin for Hex-Ray's IDA Pro disassembler that will help you retain concentration and productivity during long reversing sessions.
- `IDA Pro <https://www.hex-rays.com/products/ida/index.shtml>`_ - A Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger.
- `IDA Sploiter <http://thesprawl.org/projects/ida-sploiter/>`_ - IDA Sploiter is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's capabilities as an exploit development and vulnerability research tool.
- `IDAPython <https://github.com/idapython/>`_ - An IDA plugin which makes it possible to write scripts for IDA in the Python programming language. 
- `Immunity Debugger <http://debugger.immunityinc.com/>`_ - A powerful new way to write exploits and analyze malware.
- `JAD <http://varaneckas.com/jad/>`_ - JAD Java Decompiler.
- `Jadx <https://github.com/skylot/jadx>`_ - Decompile Android files.
- `JD-GUI <http://jd.benow.ca>`_ - Aims to develop tools in order to decompile and analyze Java 5 “byte code” and the later versions.
- `Keystone Engine <http://www.keystone-engine.org>`_ - A lightweight multi-platform, multi-architecture assembler framework.
- `Krakatau <https://github.com/Storyyeller/Krakatau>`_ - Java decompiler, assembler, and disassembler.
- `Manticore <https://github.com/trailofbits/manticore>`_ - Prototyping tool for dynamic binary analysis, with support for symbolic execution, taint analysis, and binary instrumentation.
- `MARA Framework <https://github.com/xtiankisutsa/MARA_Framework>`_ - A Mobile Application Reverse engineering and Analysis Framework.
- `Medusa <https://github.com/wisk/medusa>`_ - A disassembler designed to be both modular and interactive.
- `MegaDumper <https://github.com/CodeCracker-Tools/MegaDumper>`_ - Dump native and .NET assemblies.
- `Mona.py <https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/>`_ - PyCommand for Immunity Debugger that replaces and improves on pvefindaddr.
- `OllyDbg <http://www.ollydbg.de>`_ - An x86 debugger that emphasizes binary code analysis.
- `Paimei <https://github.com/OpenRCE/paimei>`_ - Reverse engineering framework, includes PyDBG, PIDA, pGRAPH.
- `PEDA <https://github.com/longld/peda>`_ - Python Exploit Development Assistance for GDB.
- `Plasma <https://github.com/joelpx/plasma>`_ - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code.
- `Procyon <https://bitbucket.org/mstrobel/procyon>`_ - A modern open-source Java decompiler.
- `Pyew <https://github.com/joxeankoret/pyew>`_ - Command line hexadecimal editor and disassembler, mainly to analyze malware.
- `Qira <http://qira.me>`_ - QEMU Interactive Runtime Analyser.
- `R2MSDN <https://github.com/newlog/r2msdn>`_ - R2 plugin to add MSDN documentation URLs and parameter names to imported function calls.
- `RABCDAsm <https://github.com/CyberShadow/RABCDAsm>`_ - Robust ABC (ActionScript Bytecode) [Dis-]Assembler.
- `Radare2 <http://www.radare.org>`_ - Opensource, crossplatform reverse engineering framework.
- `Redexer <https://github.com/plum-umd/redexer>`_ - A reengineering tool that manipulates Android app binaries.
- `ScratchABit <https://github.com/pfalcon/ScratchABit>`_ - Easily retargetable and hackable interactive disassembler with IDAPython-compatible plugin API.
- `Shed <https://github.com/enkomio/shed>`_ - .NET runtime inspector.
- `Simplify <https://github.com/CalebFenton/simplify>`_ - Generic Android Deobfuscator.
- `Smali <https://github.com/JesusFreke/smali>`_ - Smali/baksmali is an assembler/disassembler for the dex format used by dalvik, Android's Java VM implementation.
- `Toolbag <https://github.com/aaronportnoy/toolbag>`_ - The IDA Toolbag is a plugin providing supplemental functionality to Hex-Rays IDA Pro disassembler.
- `Ufgraph <https://github.com/bfosterjr/ufgraph>`_ - A simple script which parses the output of the uf (un-assemble function) command in windbg and uses graphviz to generate a control flow graph as a PNG/SVG/PDF/GIF (see -of option) and displays it.
- `Uncompyle <https://github.com/gstarnberger/uncompyle>`_ - Decompile Python 2.7 binaries (.pyc).
- `Unicorn Engine <http://www.unicorn-engine.org>`_ - A lightweight, multi-platform, multi-architecture CPU emulator framework based on QEMU.
- `Voltron <https://github.com/snare/voltron>`_ - An extensible debugger UI toolkit written in Python. It aims to improve the user experience of various debuggers (LLDB, GDB, VDB and WinDbg) by enabling the attachment of utility views that can retrieve and display data from the debugger host.
- `WinDbg <https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit>`_ - Windows Driver Kit and WinDbg.
- `WinHex <http://www.winhex.com/winhex/>`_ - A hexadecimal editor, helpful in the realm of computer forensics, data recovery, low-level data processing, and IT security.
- `Unlinker <https://github.com/jonwil/unlinker>`_ - Unlinker is a tool that can rip functions out of Visual C++ compiled binaries and produce Visual C++ COFF object files.
- `UPX <https://upx.github.io>`_ - The Ultimate Packer for eXecutables.
- `X64_dbg <http://x64dbg.com>`_ - An open-source x64/x32 debugger for windows.
- `Xxxswf <https://bitbucket.org/Alexander_Hanel/xxxswf>`_ - A Python script for analyzing Flash files.
- `YaCo <https://github.com/DGA-MI-SSI/YaCo>`_ - An Hex-Rays IDA plugin. When enabled, multiple users can work simultaneously on the same binary. Any modification done by any user is synchronized through git version control.

Social Engineering
==================

Framework
---------

- `SET <https://github.com/trustedsec/social-engineer-toolkit>`_ - The Social-Engineer Toolkit from TrustedSec.

Harvester
---------

- `Creepy <http://www.geocreepy.com>`_ - A geolocation OSINT tool.
- `Github-dorks <https://github.com/techgaun/github-dorks>`_ - CLI tool to scan github repos/organizations for potential sensitive information leak.
- `Maltego <https://www.paterva.com>`_ - Proprietary software for open source intelligence and forensics, from Paterva.
- `Metagoofil <https://github.com/laramies/metagoofil>`_ - Metadata harvester.
- `TheHarvester <http://www.edge-security.com/theharvester.php>`_ - E-mail, subdomain and people names harvester.
- `TTSL <https://github.com/dchrastil/TTSL>`_ - Tool to scrape LinkedIn.

Phishing
--------

- `CredSniper <https://github.com/ustayready/CredSniper>`_ - A phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens.
- `Whatsapp-phishing <https://github.com/Mawalu/whatsapp-phishing>`_ -  Proof of principle code for running a phishing attack against the official Whatsapp Web client.
