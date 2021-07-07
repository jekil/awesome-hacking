=================
 Awesome Hacking
=================

Awesome hacking is a curated list of **hacking tools** for hackers, pentesters and security researchers.
Its goal is to collect, classify and make awesome tools easy to find by humans, creating a **toolset** you can
checkout and update with one command.

This is not only a curated list, it is also a complete and updated toolset you can download with one-command! 

You can download all the tools with the following command::

    git clone --recursive https://github.com/jekil/awesome-hacking.git

To update it run the following command::

    git pull

Every kind of **contribution** is really appreciated! Follow the `contribute <https://awesomehacking.org/contribute.html>`_.

*If you enjoy this work, please keep it alive contributing or just sharing it!* - `@jekil <https://twitter.com/jekil>`_

.. contents:: Table of Contents
   :depth: 2
   :backlinks: entry

CTF Tools
=========

- `CTFd <https://ctfd.io>`_ - CTF in a can. Easily modifiable and has everything you need to run a jeopardy style CTF.
- `CTForge <https://github.com/secgroup/ctforge>`_ - The framework developed by the hacking team from University of Venice to easily host jeopardy and attack-defense CTF security competitions. It provides the software components for running the game, namely the website and the checkbot (optional).
- `FBCTF <https://github.com/facebook/fbctf>`_ - Platform to host Capture the Flag competitions.
- `LibreCTF <https://github.com/easyctf/librectf>`_ - CTF in a box. Minimal setup required.
- `Mellivora <https://github.com/Nakiami/mellivora>`_ - A CTF engine written in PHP.
- `NightShade <https://github.com/UnrealAkama/NightShade>`_ - A simple security CTF framework.
- `OneGadget <https://github.com/david942j/one_gadget>`_ - A tool for you easy to find the one gadget RCE in libc.so.6.
- `Pwntools <https://github.com/Gallopsled/pwntools>`_ - CTF framework and exploit development library.
- `Scorebot <https://github.com/legitbs/scorebot>`_ - Platform for CTFs by Legitbs (Defcon).
- `V0lt <https://github.com/P1kachu/v0lt>`_ - Security CTF Toolkit.

Code Auditing
=============

Static Analysis
---------------

- `Brakeman <http://brakemanscanner.org>`_ - A static analysis security vulnerability scanner for Ruby on Rails applications.
- `Dr. Taint <https://github.com/toshipiazza/drtaint>`_ - A very WIP DynamoRIO module built on the Dr. Memory Framework to implement taint analysis on ARM.
- `Gosec <https://github.com/securego/gosec>`_ - Inspects source code for security problems by scanning the Go AST.
- `STACK <https://github.com/xiw/stack>`_ - A static checker for identifying unstable code.
- `ShellCheck <https://github.com/koalaman/shellcheck>`_ - A static analysis tool for shell scripts.

Cryptography
============

- `FeatherDuster <https://github.com/nccgroup/featherduster>`_ - An automated, modular cryptanalysis tool.
- `RSATool <https://github.com/ius/rsatool>`_ - Generate private key with knowledge of p and q.
- `Xortool <https://github.com/hellman/xortool>`_ - A tool to analyze multi-byte xor cipher.

Docker
======

- `DVWA <https://hub.docker.com/r/citizenstig/dvwa/>`_ - Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable.
- `Docker Bench for Security <https://hub.docker.com/r/diogomonica/docker-bench-security/>`_ - The Docker Bench for Security checks for all the automatable tests in the CIS Docker 1.6 Benchmark.
- `Kali Linux <https://hub.docker.com/r/kalilinux/kali-linux-docker/>`_ - This Kali Linux Docker image provides a minimal base install of the latest version of the Kali Linux Rolling Distribution.
- `Metasploit <https://hub.docker.com/r/remnux/metasploit/>`_ - Metasploit Framework penetration testing software (unofficial docker).
- `OWASP Juice Shop <https://hub.docker.com/r/bkimminich/juice-shop/>`_ - An intentionally insecure webapp for security trainings written entirely in Javascript which encompasses the entire OWASP Top Ten and other severe security flaws.
- `OWASP Mutillidae II <https://hub.docker.com/r/citizenstig/nowasp/>`_ - OWASP Mutillidae II Web Pen-Test Practice Application.
- `OWASP NodeGoat <https://github.com/owasp/nodegoat#option-3>`_ - An environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
- `OWASP Railsgoat <https://hub.docker.com/r/owasp/railsgoat/>`_ - A vulnerable version of Rails that follows the OWASP Top 10.
- `OWASP Security Shepherd <https://hub.docker.com/r/ismisepaul/securityshepherd/>`_ - A web and mobile application security training platform.
- `OWASP WebGoat <https://hub.docker.com/r/danmx/docker-owasp-webgoat/>`_ - A deliberately insecure Web Application.
- `OWASP ZAP <https://hub.docker.com/r/owasp/zap2docker-stable/>`_ - Current stable owasp zed attack proxy release in embedded docker container.
- `Security Ninjas <https://hub.docker.com/r/opendns/security-ninjas/>`_ - An Open Source Application Security Training Program.
- `SpamScope <https://hub.docker.com/r/fmantuano/spamscope-elasticsearch/>`_ - SpamScope (Fast Advanced Spam Analysis Tool) Elasticsearch.
- `Vulnerability as a service: Heartbleed <https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/>`_ - Vulnerability as a Service: CVE 2014-0160.
- `Vulnerability as a service: Shellshock <https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/>`_ - Vulnerability as a Service: CVE 2014-6271.
- `Vulnerable WordPress Installation <https://hub.docker.com/r/wpscanteam/vulnerablewordpress/>`_ - Vulnerable WordPress Installation.
- `WPScan <https://hub.docker.com/r/wpscanteam/wpscan/>`_ - WPScan is a black box WordPress vulnerability scanner.

Forensics
=========

File Forensics
--------------

- `Autopsy <http://www.sleuthkit.org/autopsy/>`_ - A digital forensics platform and graphical interface to The Sleuth Kit and other digital forensics tools.
- `DFF <http://www.digital-forensic.org>`_ - A Forensics Framework coming with command line and graphical interfaces. DFF can be used to investigate hard drives and volatile memory and create reports about user and system activities.
- `Docker Explorer <https://github.com/google/docker-explorer>`_ - A tool to help forensicate offline docker acquisitions.
- `Hadoop_framework <https://github.com/sleuthkit/hadoop_framework>`_ - A prototype system that uses Hadoop to process hard drive images.
- `OSXCollector <http://yelp.github.io/osxcollector/>`_ - A forensic evidence collection & analysis toolkit for OS X.
- `RegRipper3.0 <https://github.com/keydet89/RegRipper3.0>`_ - Alternative to RegRipper
- `RegRippy <https://github.com/airbus-cert/regrippy>`_ - A framework for reading and extracting useful forensics data from Windows registry hives. It is an alternative to RegRipper developed in modern Python 3.
- `Scalpel <https://github.com/sleuthkit/scalpel>`_ - An open source data carving tool.
- `Shellbags <https://github.com/williballenthin/shellbags>`_ - Investigate NT_USER.dat files.
- `SlackPirate <https://github.com/emtunc/SlackPirate>`_ - Slack Enumeration and Extraction Tool - extract sensitive information from a Slack Workspace.
- `Sleuthkit <https://github.com/sleuthkit/sleuthkit>`_ - A library and collection of command line digital forensics tools.
- `TVS_extractor <https://github.com/ITLivLab/TVS_extractor>`_ - Extracts TeamViewer screen captures.
- `Telegram-extractor <https://github.com/tsusanka/telegram-extractor>`_ - Python3 scripts to analyse the data stored in Telegram.
- `Truehunter <https://github.com/adoreste/truehunter>`_ - The goal of Truehunter is to detect encrypted containers using a fast and memory efficient approach without any external dependencies for ease of portability.

Image Forensics
---------------

- `Depix <https://github.com/beurtschipper/Depix>`_ - Recovers passwords from pixelized screenshots.

Incident Response
-----------------

- `Hunter <https://github.com/ThreatHuntingProject/hunter>`_ - A threat hunting / data analysis environment based on Python, Pandas, PySpark and Jupyter Notebook.
- `Loki <https://github.com/Neo23x0/Loki>`_ - Simple IOC and Incident Response Scanner.
- `Panorama <https://github.com/AlmCo/Panorama>`_ - It was made to generate a wide report about Windows systems, support and tested on Windows XP SP2 and up.
- `Snoopdigg <https://github.com/botherder/snoopdigg>`_ - Simple utility to ease the process of collecting evidence to find infections.

Live Analysis
-------------

- `OS X Auditor <OS X Auditor is a free Mac OS X computer forensics tool>`_ - OS X Auditor is a free Mac OS X computer forensics tool.
- `Windows-event-forwarding <https://github.com/palantir/windows-event-forwarding>`_ - A repository for using windows event forwarding for incident detection and response.

Memory Forensics
----------------

- `Rekall <http://www.rekall-forensic.com>`_ - Memory analysis framework developed by Google.
- `Volatility <https://github.com/volatilityfoundation/volatility3>`_ - Volatility is the world's most widely used framework for extracting digital artifacts from volatile memory (RAM) samples. The extraction techniques are performed completely independent of the system being investigated but offer visibility into the runtime state of the system. The framework is intended to introduce people to the techniques and complexities associated with extracting digital artifacts from volatile memory samples and provide a platform for further work into this exciting area of research.

Misc
----

- `Diffy <https://github.com/Netflix-Skunkworks/diffy>`_ - A digital forensics and incident response (DFIR) tool developed by Netflix's Security Intelligence and Response Team (SIRT). Allows a forensic investigator to quickly scope a compromise across cloud instances during an incident, and triage those instances for followup actions.
- `HxD <https://mh-nexus.de/en/hxd/>`_ - A hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size.
- `Libfvde <https://github.com/libyal/libfvde>`_ - Library and tools to access FileVault Drive Encryption (FVDE) encrypted volumes.
- `Mass_archive <https://github.com/motherboardgithub/mass_archive>`_ - A basic tool for pushing a web page to multiple archiving services at once.

Mobile
------

- `Android Forensic Toolkit <https://code.google.com/archive/p/aft/>`_ - Allows you to extract SMS records, call history, photos, browsing history, and password from an Android phone.
- `Android backup extractor <https://github.com/nelenkov/android-backup-extractor>`_ - Utility to extract and repack Android backups created with adb backup (ICS+). Largely based on BackupManagerService.java from AOSP.
- `Mem <https://github.com/MobileForensicsResearch/mem>`_ - Tool used for dumping memory from Android devices.
- `Snoopdroid <https://github.com/botherder/snoopdroid>`_ - Extract packages from an Android device.
- `WhatsApp Media Decrypt <https://github.com/ddz/whatsapp-media-decrypt>`_ - Decrypt WhatsApp encrypted media files.
- `iLEAPP <https://github.com/abrignoni/iLEAPP>`_ - iOS Logs, Events, And Plist Parser.
- `iOSbackup <https://github.com/avibrazil/iOSbackup>`_ - A Pyhotn 3 class that reads and extracts files from a password-encrypted iOS backup created by iTunes on Mac and Windows. Compatible with iOS 13.

Network Forensics
-----------------

- `Dnslog <https://github.com/stamparm/dnslog>`_ - Minimalistic DNS logging tool.
- `Dshell <https://github.com/USArmyResearchLab/Dshell>`_ - A network forensic analysis framework.
- `Passivedns <https://github.com/gamelinux/passivedns>`_ - A network sniffer that logs all DNS server replies for use in a passive DNS setup.
- `Website Evidence Collector <https://github.com/EU-EDPS/website-evidence-collector>`_ - The tool Website Evidence Collector (WEC) automates the website evidence collection of storage and transfer of personal data.

Hardware Hacking
================

Computer
--------

- `Kbd-audio <https://github.com/ggerganov/kbd-audio>`_ - Tools for capturing and analysing keyboard input paired with microphone capture.
- `LimeSDR-Mini <https://github.com/myriadrf/LimeSDR-Mini>`_ - The LimeSDR-Mini board provides a hardware platform for developing and prototyping high-performance and logic-intensive digital and RF designs using Altera’s MAX10 FPGA and Lime Microsystems transceiver.
- `NSA-B-GONE <https://github.com/zakqwy/NSA-B-GONE>`_ - Thinkpad X220 board that disconnects the webcam and microphone data lines.

Intelligence
============

- `Attackintel <https://github.com/gr4ym4ntx/attackintel>`_ - A python script to query the MITRE ATT&CK API for tactics, techniques, mitigations, & detection methods for specific threat groups.
- `Dnstwist <https://github.com/elceef/dnstwist>`_ - Domain name permutation engine for detecting homograph phishing attacks, typo squatting, and brand impersonation.
- `IntelOwl <https://github.com/certego/IntelOwl>`_ - Analyze files, domains, IPs in multiple ways from a single API at scale. 
- `MISP-maltego <https://github.com/MISP/MISP-maltego>`_ - Set of Maltego transforms to inferface with a MISP Threat Sharing instance, and also to explore the whole MITRE ATT&CK dataset.
- `Shodan-seeker <https://github.com/laincode/shodan-seeker>`_ - Command-line tool using Shodan API. Generates and downloads CSV results, diffing of historic scanning results, alerts and monitoring of specific ports/IPs, etc.
- `VIA4CVE <https://github.com/cve-search/VIA4CVE>`_ - An aggregator of the known vendor vulnerabilities database to support the expansion of information with CVEs.
- `Yeti <https://github.com/yeti-platform/yeti>`_ - Your Everyday Threat Intelligence.
- `n6 <https://github.com/CERT-Polska/n6>`_ - Automated handling of data feeds for security teams.

Library
=======

C
-

- `Libdnet <https://github.com/dugsong/libdnet>`_ - Provides a simplified, portable interface to several low-level networking routines, including network address manipulation, kernel arp cache and route table lookup and manipulation, network firewalling, network interface lookup and manipulation, IP tunnelling, and raw IP packet and Ethernet frame transmission.

Go
--

- `Garble <https://github.com/mvdan/garble>`_ - Obfuscate Go builds.

Java
----

- `Libsignal-service-java <https://github.com/whispersystems/libsignal-service-java/>`_ - A Java/Android library for communicating with the Signal messaging service.

Python
------

- `Amodem <https://github.com/romanz/amodem>`_ - Audio MODEM Communication Library in Python.
- `Dpkt <https://github.com/kbandla/dpkt>`_ - Fast, simple packet creation / parsing, with definitions for the basic TCP/IP protocols.
- `Pcapy <https://www.coresecurity.com/corelabs-research/open-source-tools/pcapy>`_ - A Python extension module that interfaces with the libpcap packet capture library. Pcapy enables python scripts to capture packets on the network. Pcapy is highly effective when used in conjunction with a packet-handling package such as Impacket, which is a collection of Python classes for constructing and dissecting network packets.
- `Plyara <https://github.com/plyara/plyara>`_ - Parse YARA rules and operate over them more easily.
- `PyBFD <https://github.com/Groundworkstech/pybfd/>`_ - Python interface to the GNU Binary File Descriptor (BFD) library.
- `PyPDF2 <http://mstamy2.github.io/PyPDF2>`_ - A utility to read and write PDFs with Python.
- `Pynids <https://jon.oberheide.org/pynids/>`_ - A python wrapper for libnids, a Network Intrusion Detection System library offering sniffing, IP defragmentation, TCP stream reassembly and TCP port scan detection. Let your own python routines examine network conversations.
- `Pypcap <https://github.com/dugsong/pypcap>`_ - This is a simplified object-oriented Python wrapper for libpcap.
- `Pyprotect <https://github.com/ga0/pyprotect>`_ - A lightweight python code protector, makes your python project harder to reverse engineer.
- `Python-idb <https://github.com/williballenthin/python-idb>`_ - Pure Python parser and analyzer for IDA Pro database files (.idb).
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
- `BOSSLive <https://bosslinux.in>`_ - An Indian GNU/Linux distribution developed by CDAC and is customized to suit Indian's digital environment. It supports most of the Indian languages.
- `BackBox <https://backbox.org>`_ - Ubuntu-based distribution for penetration tests and security assessments.
- `BlackArch <https://www.blackarch.org>`_ - Arch Linux-based distribution for penetration testers and security researchers.
- `DEFT Linux <http://www.deftlinux.net>`_ - Suite dedicated to incident response and digital forensics.
- `Fedora Security Lab <https://labs.fedoraproject.org/en/security/>`_ - A safe test environment to work on security auditing, forensics, system rescue and teaching security testing methodologies in universities and other organizations.
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
- `CAPEv2 <https://github.com/kevoreilly/CAPEv2>`_ - Malware Configuration And Payload Extraction.
- `Cuckoo Sandbox <http://www.cuckoosandbox.org>`_ - An automated dynamic malware analysis system.
- `CuckooDroid <https://github.com/idanr1986/cuckoo-droid>`_ - Automated Android Malware Analysis with Cuckoo Sandbox.
- `DECAF <https://github.com/sycurelab/DECAF>`_ - Short for Dynamic Executable Code Analysis Framework, is a binary analysis platform based on QEMU.
- `DRAKVUF Sandbox <https://github.com/CERT-Polska/drakvuf-sandbox>`_ - DRAKVUF Sandbox is an automated black-box malware analysis system with DRAKVUF engine under the hood, which does not require an agent on guest OS.
- `DroidBox <https://github.com/pjlantz/droidbox>`_ - Dynamic analysis of Android apps.
- `Hooker <https://github.com/AndroidHooker/hooker>`_ - An opensource project for dynamic analyses of Android applications.
- `Jsunpack-n <https://github.com/urule99/jsunpack-n>`_ - Emulates browser functionality when visiting a URL.
- `LiSa <https://github.com/danieluhricek/LiSa>`_ - Sandbox for automated Linux malware analysis.
- `Magento-malware-scanner <https://github.com/gwillem/magento-malware-scanner>`_ - A collection of rules and samples to detect Magento malware.
- `Malzilla <http://malzilla.sourceforge.net>`_ - Web pages that contain exploits often use a series of redirects and obfuscated code to make it more difficult for somebody to follow. MalZilla is a useful program for use in exploring malicious pages. It allows you to choose your own user agent and referrer, and has the ability to use proxies. It shows you the full source of webpages and all the HTTP headers. It gives you various decoders to try and deobfuscate javascript aswell.
- `Panda <https://github.com/panda-re/panda>`_ - Platform for Architecture-Neutral Dynamic Analysis.
- `ProbeDroid <https://github.com/ZSShen/ProbeDroid>`_ - A dynamic binary instrumentation kit targeting on Android(Lollipop) 5.0 and above.
- `PyEMU <https://code.google.com/archive/p/pyemu/>`_ - Fully scriptable IA-32 emulator, useful for malware analysis.
- `PyWinSandbox <https://github.com/karkason/pywinsandbox>`_ - Python Windows Sandbox library. Create a new Windows Sandbox machine, control it with a simple RPyC interface.
- `Pyrebox <https://github.com/Cisco-Talos/pyrebox>`_ - Python scriptable Reverse Engineering Sandbox, a Virtual Machine instrumentation and inspection framework based on QEMU.
- `Qiling <https://github.com/qilingframework/qiling>`_ - Advanced Binary Emulation framework.
- `Speakeasy <https://github.com/fireeye/speakeasy>`_ - A portable, modular, binary emulator designed to emulate Windows kernel and user mode malware.
- `Uitkyk <https://github.com/brompwnie/uitkyk>`_ - Runtime memory analysis framework to identify Android malware.
- `WScript Emulator <https://github.com/mrpapercut/wscript/>`_ - Emulator/tracer of the Windows Script Host functionality.

Honeypot
--------

- `Amun <https://github.com/zeroq/amun>`_ - Amun was the first python-based low-interaction honeypot, following the concepts of Nepenthes but extending it with more sophisticated emulation and easier maintenance.
- `Basic-auth-pot <https://github.com/bjeborn/basic-auth-pot>`_ - HTTP Basic Authentication honeyPot.
- `Bluepot <https://github.com/andrewmichaelsmith/bluepot>`_ - Bluetooth Honeypot.
- `CitrixHoneypot <https://github.com/MalwareTech/CitrixHoneypot>`_ - Detect and log CVE-2019-19781 scan and exploitation attempts.
- `Conpot <https://github.com/mushorg/conpot>`_ - ICS/SCADA honeypot.
- `Cowrie <https://www.cowrie.org>`_ - SSH honeypot, based on Kippo.
- `Dionaea <https://github.com/DinoTools/dionaea>`_ - Honeypot designed to trap malware.
- `Django-admin-honeypot <https://github.com/dmpayton/django-admin-honeypot>`_ - A fake Django admin login screen to log and notify admins of attempted unauthorized access.
- `ESPot <https://github.com/mycert/ESPot>`_ - An Elasticsearch honeypot written in NodeJS, to capture every attempts to exploit CVE-2014-3120.
- `Elastichoney <https://github.com/jordan-wright/elastichoney>`_ - A Simple Elasticsearch Honeypot.
- `Endlessh <https://github.com/skeeto/endlessh>`_ - An SSH tarpit that very slowly sends an endless, random SSH banner. It keeps SSH clients locked up for hours or even days at a time. The purpose is to put your real SSH server on another port and then let the script kiddies get stuck in this tarpit instead of bothering a real server.
- `Glastopf <https://github.com/mushorg/glastopf>`_ - Web Application Honeypot.
- `Glutton <https://github.com/mushorg/glutton>`_ - All eating honeypot.
- `HFish <https://hfish.io/>`_ - A cross platform honeypot platform developed based on golang, which has been meticulously built for enterprise security.
- `Heralding <https://github.com/johnnykv/heralding>`_ - Sometimes you just want a simple honeypot that collects credentials, nothing more. Heralding is that honeypot! Currently the following protocols are supported: ftp, telnet, ssh, rdp, http, https, pop3, pop3s, imap, imaps, smtp, vnc, postgresql and socks5.
- `HonTel <https://github.com/stamparm/hontel>`_ - A Honeypot for Telnet service. Basically, it is a Python v2.x application emulating the service inside the chroot environment. Originally it has been designed to be run inside the Ubuntu/Debian environment, though it could be easily adapted to run inside any Linux environment.
- `HoneyPy <https://github.com/foospidy/HoneyPy>`_ - A low to medium interaction honeypot.
- `HoneyTrap <https://github.com/honeytrap/honeytrap>`_ - Advanced Honeypot framework.
- `Honeyd <http://www.honeyd.org>`_ - Create a virtual honeynet.
- `Honeypot <https://github.com/Shmakov/Honeypot>`_ - Low interaction honeypot that displays real time attacks.
- `Honeything <https://github.com/omererdem/honeything>`_ - A honeypot for Internet of TR-069 things. It's designed to act as completely a modem/router that has RomPager embedded web server and supports TR-069 (CWMP) protocol.
- `HonnyPotter <https://github.com/MartinIngesen/HonnyPotter>`_ - A WordPress login honeypot for collection and analysis of failed login attempts.
- `Kippo <https://github.com/desaster/kippo>`_ - A medium interaction SSH honeypot designed to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.
- `Kippo-graph <https://github.com/ikoniaris/kippo-graph>`_ - Visualize statistics from a Kippo SSH honeypot.
- `MHN <https://github.com/threatstream/mhn>`_ - Multi-snort and honeypot sensor management, uses a network of VMs, small footprint SNORT installations, stealthy dionaeas, and a centralized server for management.
- `MTPot <https://github.com/Cymmetria/MTPot>`_ - Open Source Telnet Honeypot.
- `Maildb <https://github.com/kevthehermit/Maildb>`_ - Python Web App to Parse and Track Email and http Pcap Files.
- `Mailoney <https://github.com/awhitehatter/mailoney>`_ - A SMTP Honeypot I wrote just to have fun learning Python.
- `Miniprint <https://github.com/sa7mon/miniprint>`_ - A medium interaction printer honeypot.
- `Mnemosyne <https://github.com/johnnykv/mnemosyne>`_ - A normalizer for honeypot data; supports Dionaea.
- `MongoDB-HoneyProxy <https://github.com/Plazmaz/MongoDB-HoneyProxy>`_ - A honeypot proxy for mongodb. When run, this will proxy and log all traffic to a dummy mongodb server.
- `MysqlPot <https://github.com/schmalle/MysqlPot>`_ - A mysql honeypot, still very very early stage.
- `NoSQLPot <https://github.com/torque59/nosqlpot>`_ - The NoSQL Honeypot Framework.
- `Nodepot <https://github.com/schmalle/Nodepot>`_ - A nodejs web application honeypot.
- `OWASP-Honeypot <https://github.com/zdresearch/OWASP-Honeypot>`_ - An open source software in Python language which designed for creating honeypot and honeynet in an easy and secure way.
- `OpenCanary <http://opencanary.org/>`_ - A daemon that runs several canary versions of services that alerts when a service is (ab)used.
- `Phoneyc <https://github.com/buffer/phoneyc>`_ - Pure Python honeyclient implementation.
- `Phpmyadmin_honeypot <https://github.com/gfoss/phpmyadmin_honeypot>`_ - A simple and effective phpMyAdmin honeypot.
- `Servletpot <https://github.com/schmalle/servletpot>`_ - Web application Honeypot.
- `Shadow Daemon <https://shadowd.zecure.org>`_ - A modular Web Application Firewall / High-Interaction Honeypot for PHP, Perl & Python apps.
- `Shiva <https://github.com/shiva-spampot/shiva>`_ - Spam Honeypot with Intelligent Virtual Analyzer, is an open but controlled relay Spam Honeypot (SpamPot), built on top of Lamson Python framework, with capability of collecting and analyzing all spam thrown at it.
- `Smart-honeypot <https://github.com/freak3dot/smart-honeypot>`_ - PHP Script demonstrating a smart honey pot.
- `Snare <https://github.com/mushorg/snare>`_ - Super Next generation Advanced Reactive honEypot
- `SpamScope <https://github.com/SpamScope/spamscope>`_ - Fast Advanced Spam Analysis Tool.
- `StrutsHoneypot <https://github.com/Cymmetria/StrutsHoneypot>`_ - Struts Apache 2 based honeypot as well as a detection module for Apache 2 servers.
- `T-Pot <https://github.com/dtag-dev-sec/tpotce>`_ - The All In One Honeypot Platform.
- `Tango <https://github.com/aplura/Tango>`_ - Honeypot Intelligence with Splunk.
- `Tanner <https://github.com/mushorg/tanner>`_ - A remote data analysis and classification service to evaluate HTTP requests and composing the response then served by SNARE. TANNER uses multiple application vulnerability type emulation techniques when providing responses for SNARE. In addition, TANNER provides Dorks for SNARE powering its luring capabilities.
- `Thug <https://github.com/buffer/thug>`_ - Low interaction honeyclient, for investigating malicious websites.
- `Twisted-honeypots <https://github.com/lanjelot/twisted-honeypots>`_ - SSH, FTP and Telnet honeypots based on Twisted.
- `Wetland <https://github.com/ohmyadd/wetland>`_ - A high interaction SSH honeypot.
- `Wordpot <https://github.com/gbrindisi/wordpot>`_ - A WordPress Honeypot.
- `Wp-smart-honeypot <https://github.com/freak3dot/wp-smart-honeypot>`_ - WordPress plugin to reduce comment spam with a smarter honeypot.

Intelligence
------------

- `CobaltStrikeParser <https://github.com/Sentinel-One/CobaltStrikeParser>`_ - Python parser for CobaltStrike Beacon's configuration.
- `Cobaltstrike <https://github.com/Te-k/cobaltstrike>`_ - Code and yara rules to detect and analyze Cobalt Strike.
- `MISP Modules <https://github.com/MISP/misp-modules>`_ - Modules for expansion services, import and export in MISP.
- `Passivedns-client <https://github.com/chrislee35/passivedns-client>`_ - Provides a library and a query tool for querying several passive DNS providers.
- `Pybeacon <https://github.com/nccgroup/pybeacon>`_ - A collection of scripts for dealing with Cobalt Strike beacons in Python.
- `Rt2jira <https://github.com/fireeye/rt2jira>`_ - Convert RT tickets to JIRA tickets.

Ops
---

- `Al-khaser <https://github.com/LordNoteworthy/al-khaser>`_ - Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.
- `BASS <https://github.com/Cisco-Talos/BASS>`_ - BASS Automated Signature Synthesizer.
- `CSCGuard <https://github.com/glinares/CSCGuard>`_ - Protects and logs suspicious and malicious usage of .NET CSC.exe and Runtime C# Compilation.
- `CapTipper <https://github.com/omriher/CapTipper>`_ - A python tool to analyze, explore and revive HTTP malicious traffic.
- `FLARE <https://github.com/fireeye/flare-vm>`_ - A fully customizable, Windows-based security distribution for malware analysis, incident response, penetration testing, etc.
- `FakeNet-NG <https://github.com/fireeye/flare-fakenet-ng>`_ - A next generation dynamic network analysis tool for malware analysts and penetration testers. It is open source and designed for the latest versions of Windows.
- `Google-play-crawler <https://github.com/Akdeniz/google-play-crawler>`_ - Google-play-crawler is simply Java tool for searching android applications on GooglePlay, and also downloading them.
- `Googleplay-api <https://github.com/egirault/googleplay-api>`_ - An unofficial Python API that let you search, browse and download Android apps from Google Play (formerly Android Market).
- `Grimd <https://github.com/looterz/grimd>`_ - Fast dns proxy that can run anywhere, built to black-hole internet advertisements and malware servers.
- `Hidden <https://github.com/JKornev/hidden>`_ - Windows driver with usermode interface which can hide objects of file-system and registry, protect processes and etc.
- `ImaginaryC2 <https://github.com/felixweyne/imaginaryC2>`_ - A python tool which aims to help in the behavioral (network) analysis of malware. Imaginary C2 hosts a HTTP server which captures HTTP requests towards selectively chosen domains/IPs. Additionally, the tool aims to make it easy to replay captured Command-and-Control responses/served payloads.
- `Irma <https://github.com/quarkslab/irma>`_ - IRMA is an asynchronous & customizable analysis system for suspicious files. 
- `KLara <https://github.com/KasperskyLab/klara>`_ - A project is aimed at helping Threat Intelligence researchers hunt for new malware using Yara.
- `Kraken <https://github.com/botherder/kraken>`_ - Cross-platform Yara scanner written in Go.
- `Malboxes <https://github.com/GoSecure/malboxes>`_ - Builds malware analysis Windows VMs so that you don't have to.
- `Mquery <https://github.com/CERT-Polska/mquery>`_ - YARA malware query accelerator (web frontend).
- `Node-appland <https://github.com/dweinstein/node-appland>`_ - NodeJS tool to download APKs from appland.
- `Node-aptoide <https://github.com/dweinstein/node-aptoide>`_ - NodeJS to download APKs from aptoide.
- `Node-google-play <https://github.com/dweinstein/node-google-play>`_ - Call Google Play APIs from Node.
- `Pafish <https://github.com/a0rtega/pafish>`_ - A demonstration tool that employs several techniques to detect sandboxes and analysis environments in the same way as malware families do.

Source Code
-----------

- `Android-malware <https://github.com/ashishb/android-malware>`_ - Collection of android malware samples.
- `AsyncRAT-C-Sharp <https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp>`_ - Open-Source Remote Administration Tool For Windows C# (RAT).
- `BYOB <https://github.com/malwaredllc/byob>`_ - An open-source project that provides a framework for security researchers and developers to build and operate a basic botnet to deepen their understanding of the sophisticated malware that infects millions of devices every year and spawns modern botnets, in order to improve their ability to develop counter-measures against these threats.
- `BlackHole <https://github.com/hussein-aitlahcen/BlackHole>`_ - C# RAT (Remote Administration Tool).
- `Carberp <https://github.com/hzeroo/Carberp>`_ - Carberp leaked source code.
- `Coldfire <https://github.com/redcode-labs/Coldfire>`_ - Golang malware development library.
- `Fancybear <https://github.com/rickey-g/fancybear>`_ - Fancy Bear Source Code.
- `LOLBAS <https://github.com/LOLBAS-Project/LOLBAS>`_ - Living Off The Land Binaries And Scripts - (LOLBins and LOLScripts).
- `Mirai <https://github.com/jgamblin/Mirai-Source-Code>`_ - Leaked Mirai Source Code for Research/IoC Development Purposes.
- `Morris Worm <https://github.com/arialdomartini/morris-worm>`_ - The original Morris Worm source code.
- `SvcHostDemo <https://github.com/apriorit/SvcHostDemo>`_ - Demo service that runs in svchost.exe.
- `TinyNuke <https://github.com/rossja/TinyNuke>`_ - Zeus-style banking trojan.
- `Zerokit <https://github.com/Darkabode/zerokit>`_ - Zerokit/GAPZ rootkit (non buildable and only for researching).
- `Zeus <https://github.com/Visgean/Zeus>`_ - Zeus version 2.0.8.9, leaked in 2011.

Static Analysis
---------------

- `APKinspector <https://github.com/honeynet/apkinspector/>`_ - A powerful GUI tool for analysts to analyze the Android applications.
- `Aa-tools <https://github.com/JPCERTCC/aa-tools>`_ - Artifact analysis tools by JPCERT/CC Analysis Center.
- `Androwarn <https://github.com/maaaaz/androwarn/>`_ - Detect and warn the user about potential malicious behaviours developed by an Android application.
- `ApkAnalyser <https://github.com/sonyxperiadev/ApkAnalyser>`_ - A static, virtual analysis tool for examining and validating the development work of your Android app.
- `Argus-SAF <http://pag.arguslab.org/argus-saf>`_ - Argus static analysis framework.
- `CAPA <https://github.com/fireeye/capa>`_ - The FLARE team's open-source tool to identify capabilities in executable files.
- `CFGScanDroid <https://github.com/douggard/CFGScanDroid>`_ - Control Flow Graph Scanning for Android.
- `ConDroid <https://github.com/JulianSchuette/ConDroid>`_ - Symbolic/concolic execution of Android apps.
- `DroidLegacy <https://bitbucket.org/srl/droidlegacy>`_ - Static analysis scripts.
- `FSquaDRA <https://github.com/zyrikby/FSquaDRA>`_ - Fast detection of repackaged Android applications based on the comparison of resource files included into the package.
- `Floss <https://github.com/fireeye/flare-floss>`_ - FireEye Labs Obfuscated String Solver. Automatically extract obfuscated strings from malware.
- `Inspeckage <https://github.com/ac-pm/Inspeckage>`_ - Android Package Inspector - dynamic analysis with api hooks, start unexported activities and more.
- `Maldrolyzer <https://github.com/maldroid/maldrolyzer>`_ - Simple framework to extract "actionable" data from Android malware (C&Cs, phone numbers, etc).
- `PEfile <https://github.com/erocarrera/pefile>`_ - Read and work with Portable Executable (aka PE) files.
- `PEview <http://wjradburn.com/software/>`_ - A quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files.
- `PScout <http://pscout.csl.toronto.edu>`_ - Analyzing the Android Permission Specification.
- `Pdfminer <https://euske.github.io/pdfminer/>`_ - A tool for extracting information from PDF documents.
- `Peepdf <http://eternal-todo.com/tools/peepdf-pdf-analysis-tool>`_ - A Python tool to explore PDF files in order to find out if the file can be harmful or not. The aim of this tool is to provide all the necessary components that a security researcher could need in a PDF analysis without using 3 or 4 tools to make all the tasks.
- `Quark-engine <https://github.com/quark-engine/quark-engine>`_ - A trust-worthy, practical tool that's ready to boost up your malware reverse engineering.
- `Smali-CFGs <https://github.com/EugenioDelfa/Smali-CFGs>`_ - Smali Control Flow Graph's.
- `SmaliSCA <https://github.com/dorneanu/smalisca>`_ - Smali Static Code Analysis.
- `Sysinternals Suite <https://technet.microsoft.com/en-us/sysinternals/bb842062>`_ - The Sysinternals Troubleshooting Utilities.
- `Yara <http://virustotal.github.io/yara/>`_ - Identify and classify malware samples.

Network
=======

Analysis
--------

- `Bro <http://www.bro.org>`_ - A powerful network analysis framework that is much different from the typical IDS you may know.
- `Fatt <https://github.com/0x4D31/fatt>`_ - A pyshark based script for extracting network metadata and fingerprints from pcap files and live network traffic.
- `Nidan <https://github.com/michelep/Nidan>`_ - An active network monitor tool.
- `Pytbull <http://pytbull.sourceforge.net>`_ - A python based flexible IDS/IPS testing framework.
- `Sguil <http://bammv.github.io/sguil/index.html>`_ - Sguil (pronounced sgweel) is built by network security analysts for network security analysts. Sguil's main component is an intuitive GUI that provides access to realtime events, session data, and raw packet captures.
- `Winshark <https://github.com/airbus-cert/Winshark>`_ - A wireshark plugin to instrument ETW.

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
- `Dsniff <https://www.monkey.org/~dugsong/dsniff/>`_ - A collection of tools for network auditing and pentesting.
- `Justniffer <http://justniffer.sourceforge.net/>`_ - Just A Network TCP Packet Sniffer. Justniffer is a network protocol analyzer that captures network traffic and produces logs in a customized way, can emulate Apache web server log files, track response times and extract all "intercepted" files from the HTTP traffic.
- `Moloch <https://github.com/aol/moloch>`_ - Moloch is a open source large scale full PCAP capturing, indexing and database system.
- `Net-creds <https://github.com/DanMcInerney/net-creds>`_ - Sniffs sensitive data from interface or pcap.
- `Netsniff-ng <http://netsniff-ng.org>`_ - A Swiss army knife for your daily Linux network plumbing.
- `NetworkMiner <http://www.netresec.com/?page=NetworkMiner>`_ - A Network Forensic Analysis Tool (NFAT).
- `OpenFPC <http://www.openfpc.org>`_ - OpenFPC is a set of scripts that combine to provide a lightweight full-packet network traffic recorder and buffering tool. Its design goal is to allow non-expert users to deploy a distributed network traffic recorder on COTS hardware while integrating into existing alert and log tools.
- `Openli <https://github.com/wanduow/openli>`_ - Open Source ETSI compliant Lawful Intercept software.
- `PF_RING <http://www.ntop.org/products/packet-capture/pf_ring/>`_ - PF_RING™ is a Linux kernel module and user-space framework that allows you to process packets at high-rates while providing you a consistent API for packet processing applications.
- `Termshark <https://github.com/gcla/termshark>`_ - A terminal UI for tshark, inspired by Wireshark.
- `WebPcap <https://github.com/sparrowprince/WebPcap>`_ - A web-based packet analyzer (client/server architecture). Useful for analyzing distributed applications or embedded devices.
- `Wireshark <https://www.wireshark.org>`_ - A free and open-source packet analyzer.

Penetration Testing
===================

DoS
---

- `DHCPig <https://github.com/kamorin/DHCPig>`_ - DHCP exhaustion script written in python using scapy network library.
- `LOIC <https://github.com/NewEraCracker/LOIC/>`_ - Low Orbit Ion Cannon - An open source network stress tool, written in C#. Based on Praetox's LOIC project.
- `Memcrashed <https://github.com/649/Memcrashed-DDoS-Exploit>`_ - DDoS attack tool for sending forged UDP packets to vulnerable Memcached servers obtained using Shodan API.
- `Sockstress <https://github.com/defuse/sockstress>`_ - Sockstress (TCP DoS) implementation.
- `T50 <http://t50.sf.net/>`_ - The more fast network stress tool.
- `Torshammer <https://github.com/dotfighter/torshammer>`_ - Tor's hammer. Slow post DDOS tool written in python.
- `UFONet <http://ufonet.03c8.net>`_ - Abuses OSI Layer 7-HTTP to create/manage 'zombies' and to conduct different attacks using; GET/POST, multithreading, proxies, origin spoofing methods, cache evasion techniques, etc.

Exploiting
----------

- `AttackSurfaceAnalyzer <https://github.com/microsoft/AttackSurfaceAnalyzer>`_ - Attack Surface Analyzer can help you analyze your operating system's security configuration for changes during software installation.
- `Bashfuscator <https://github.com/Bashfuscator/Bashfuscator>`_ - A fully configurable and extendable Bash obfuscation framework. This tool is intended to help both red team and blue team.
- `BeEF <http://beefproject.com>`_ - The Browser Exploitation Framework Project.
- `BugId <https://github.com/SkyLined/BugId>`_ - Detect, analyze and uniquely identify crashes in Windows applications.
- `CCAT <https://github.com/RhinoSecurityLabs/ccat>`_ - Cloud Container Attack Tool (CCAT) is a tool for testing security of container environments.
- `Commix <http://www.commixproject.com>`_ - Automated All-in-One OS Command Injection and Exploitation Tool.
- `DLLInjector <https://github.com/OpenSecurityResearch/dllinjector>`_ - Inject dlls in processes.
- `DefenderCheck <https://github.com/matterpreter/DefenderCheck>`_ - Identifies the bytes that Microsoft Defender flags on.
- `Donut <https://github.com/TheWover/donut>`_ - Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters.
- `Drupwn <https://github.com/immunIT/drupwn>`_ - Drupal enumeration & exploitation tool.
- `EfiGuard <https://github.com/Mattiwatti/EfiGuard>`_ - Disable PatchGuard and DSE at boot time.
- `EtherSploit-IP <https://github.com/thiagoralves/EtherSploit-IP>`_ - Exploiting Allen-Bradley E/IP PLCs.
- `Evilgrade <https://github.com/infobyte/evilgrade>`_ - The update explotation framework.
- `Exe2hex <https://github.com/g0tmi1k/exe2hex>`_ - Inline file transfer using in-built Windows tools (DEBUG.exe or PowerShell).
- `Fathomless <https://github.com/xor-function/fathomless>`_ - A collection of different programs for network red teaming.
- `Gorsair <https://github.com/Ullaakut/Gorsair>`_ - Gorsair hacks its way into remote docker containers that expose their APIs.
- `Infection Monkey <https://github.com/guardicore/monkey>`_ - An open source security tool for testing a data center's resiliency to perimeter breaches and internal server infection. The Monkey uses various methods to self propagate across a data center and reports success to a centralized Monkey Island server.
- `Kube-hunter <https://github.com/aquasecurity/kube-hunter>`_ - Hunt for security weaknesses in Kubernetes clusters.
- `LAVA <https://github.com/panda-re/lava>`_ - Large-scale Automated Vulnerability Addition.
- `Linux Exploit Suggester <https://github.com/PenturaLabs/Linux_Exploit_Suggester>`_ - Linux Exploit Suggester; based on operating system release number.
- `Linux-exploit-suggester <https://github.com/mzet-/linux-exploit-suggester>`_ - Linux privilege escalation auditing tool.
- `MSDAT <https://github.com/quentinhardy/msdat>`_ - Microsoft SQL Database Attacking Tool is an open source penetration testing tool that tests the security of Microsoft SQL Databases remotely.
- `Macrome <https://github.com/michaelweber/Macrome>`_ - Excel Macro Document Reader/Writer for Red Teamers & Analysts
- `Metasploit Framework <http://www.metasploit.com/>`_ - Exploitation framework.
- `MeterSSH <https://github.com/trustedsec/meterssh>`_ - A way to take shellcode, inject it into memory then tunnel whatever port you want to over SSH to mask any type of communications as a normal SSH connection. The way it works is by injecting shellcode into memory, then wrapping a port spawned (meterpeter in this case) by the shellcode over SSH back to the attackers machine. Then connecting with meterpreter's listener to localhost will communicate through the SSH proxy, to the victim through the SSH tunnel. All communications are relayed through the SSH tunnel and not through the network.
- `Nessus <http://www.tenable.com/products/nessus-vulnerability-scanner>`_ - Vulnerability, configuration, and compliance assessment.
- `Nexpose <https://www.rapid7.com/products/nexpose/>`_ - Vulnerability Management & Risk Management Software.
- `Nishang <https://github.com/samratashok/nishang>`_ - Offensive PowerShell for red team, penetration testing and offensive security.
- `OpenVAS <http://www.openvas.org>`_ - Open Source vulnerability scanner and manager.
- `PEzor <https://github.com/phra/PEzor>`_ - Open-Source PE Packer.
- `PRET <https://github.com/RUB-NDS/PRET>`_ - Printer Exploitation Toolkit. The tool that made dumpster diving obsolete.
- `PSKernel-Primitives <https://github.com/FuzzySecurity/PSKernel-Primitives>`_ - Exploit primitives for PowerShell.
- `Peirates <https://github.com/inguardians/peirates>`_ - A Kubernetes penetration tool, enables an attacker to escalate privilege and pivot through a Kubernetes cluster. It automates known techniques to steal and collect service accounts, obtain further code execution, and gain control of the cluster.
- `PowerSploit <https://github.com/PowerShellMafia/PowerSploit/>`_ - A PowerShell Post-Exploitation Framework.
- `ROP Gadget <http://shell-storm.org/project/ROPgadget/>`_ - Framework for ROP exploitation.
- `Ropper <https://github.com/sashs/Ropper>`_ - Display information about files in different file formats and find gadgets to build rop chains for different architectures (x86/x86_64, ARM/ARM64, MIPS, PowerPC, SPARC64). For disassembly ropper uses the awesome Capstone Framework.
- `Routersploit <https://github.com/reverse-shell/routersploit>`_ - Automated penetration testing software for router.
- `Rupture <https://github.com/dionyziz/rupture/>`_ - A framework for BREACH and other compression-based crypto attacks.
- `SPARTA <http://sparta.secforce.com>`_ - Network Infrastructure Penetration Testing Tool.
- `Shark <https://github.com/9176324/Shark>`_ - Turn off PatchGuard in real time for win7 (7600) ~ win10 (18950).
- `SharpBlock <https://github.com/CCob/SharpBlock>`_ - A method of bypassing EDR's active projection DLL's by preventing entry point execution.
- `SharpShooter <https://github.com/mdsecactivebreach/SharpShooter>`_ - Payload Generation Framework.
- `ShellcodeCompiler <https://github.com/NytroRST/ShellcodeCompiler>`_ - A program that compiles C/C++ style code into a small, position-independent and NULL-free shellcode for Windows (x86 and x64) and Linux (x86 and x64). It is possible to call any Windows API function or Linux syscall in a user-friendly way.
- `Shellen <https://github.com/merrychap/shellen>`_ - Interactive shellcoding environment to easily craft shellcodes.
- `Shellsploit <https://github.com/b3mb4m/shellsploit-framework>`_ - Let's you generate customized shellcodes, backdoors, injectors for various operating system. And let's you obfuscation every byte via encoders.
- `Spoodle <https://github.com/vjex/spoodle>`_ - A mass subdomain + poodle vulnerability scanner.
- `SysWhispers <https://github.com/jthuraisamy/SysWhispers#syswhispers>`_ - AV/EDR evasion via direct system calls.
- `Unicorn <https://github.com/trustedsec/unicorn>`_ - Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18.
- `Veil Framework <https://www.veil-framework.com>`_ - A tool designed to generate metasploit payloads that bypass common anti-virus solutions.
- `Vuls <https://github.com/future-architect/vuls>`_ - Vulnerability scanner for Linux/FreeBSD, agentless, written in Go.
- `Windows Exploit Suggester <https://github.com/GDSSecurity/Windows-Exploit-Suggester>`_ - Detects potential missing patches on the target.
- `Ysoserial.net <https://github.com/pwntester/ysoserial.net>`_ - Deserialization payload generator for a variety of .NET formatters.
- `Zarp <https://github.com/hatRiot/zarp>`_ - Network Attack Tool.
- `expdevBadChars <https://github.com/mgeeky/expdevBadChars>`_ - Bad Characters highlighter for exploit development purposes supporting multiple input formats while comparing.

Exploits
--------

- `Apache-uaf <https://github.com/hannob/apache-uaf>`_ - Apache use after free bug infos / ASAN stack traces.
- `BlueGate <https://github.com/ollypwn/BlueGate>`_ - PoC (DoS + scanner) for CVE-2020-0609 & CVE-2020-0610 - RD Gateway RCE.
- `Bluedroid <https://github.com/JiounDai/Bluedroid>`_ - PoCs of Vulnerabilities on Bluedroid.
- `Broadpwn <https://github.com/mailinneberg/Broadpwn>`_ - Broadpwn bug (CVE-2017-9417).
- `CVE-2018-8120 <https://github.com/bigric3/cve-2018-8120>`_ - CVE-2018-8120.
- `CVE-2018-8897 <https://github.com/nmulasmajic/CVE-2018-8897>`_ - Implements the POP/MOV SS (CVE-2018-8897) vulnerability by bugchecking the machine (local DoS).
- `CVE-2019-0604 <https://github.com/k8gege/CVE-2019-0604>`_ - cve-2019-0604 SharePoint RCE exploit.
- `CVE-2019-18935 <https://github.com/noperator/CVE-2019-18935>`_ - RCE exploit for a .NET deserialization vulnerability in Telerik UI for ASP.NET AJAX.
- `CVE-2019-6453 <https://github.com/proofofcalc/cve-2019-6453-poc>`_ - Proof of calc for CVE-2019-6453 (Mirc exploit).
- `CVE-2020-10560 <https://github.com/kevthehermit/CVE-2020-10560>`_ - OSSN Arbitrary File Read
- `CVE-2020-11651 <https://github.com/kevthehermit/CVE-2020-11651>`_ - PoC for CVE-2020-11651.
- `CVE-2020-1301 <https://github.com/shubham0d/CVE-2020-1301>`_ - POC exploit for SMBLost vulnerability (CVE-2020-1301)
- `CVE-2020-1350 <https://github.com/tinkersec/cve-2020-1350>`_ - Bash Proof-of-Concept (PoC) script to exploit SIGRed (CVE-2020-1350). Achieves Domain Admin on Domain Controllers running Windows Server 2003 up to Windows Server 2019.
- `CVE-2020-1350-DoS <https://github.com/maxpl0it/CVE-2020-1350-DoS>`_ - A denial-of-service proof-of-concept for CVE-2020-1350.
- `CVE-2020-1472 <https://github.com/VoidSec/CVE-2020-1472>`_ - Exploit Code for CVE-2020-1472 aka Zerologon.
- `CVE-2020-1472_2 <https://github.com/dirkjanm/CVE-2020-1472>`_ - PoC for Zerologon
- `CVE-2021-26855_PoC <https://github.com/alt3kx/CVE-2021-26855_PoC>`_ - SSRF payloads (CVE-2021-26855) over Exchange Server 2019.
- `CVE-2021-31166 <https://github.com/0vercl0k/CVE-2021-31166>`_ - Proof of concept for CVE-2021-31166, a remote HTTP.sys use-after-free triggered remotely.
- `Chakra-2016-11 <https://github.com/theori-io/chakra-2016-11>`_ - Proof-of-Concept exploit for Edge bugs (CVE-2016-7200 & CVE-2016-7201).
- `Chimay-Red <https://github.com/BigNerd95/Chimay-Red>`_ - Working POC of Mikrotik exploit from Vault 7 CIA Leaks.
- `Desharialize <https://github.com/Voulnet/desharialize>`_ - Easy mode to Exploit CVE-2019-0604 (Sharepoint XML Deserialization Unauthenticated RCE).
- `ES File Explorer Open Port Vulnerability <https://github.com/fs0c131y/ESFileExplorerOpenPortVuln>`_ - ES File Explorer Open Port Vulnerability - CVE-2019-6447.
- `HolicPOC <https://github.com/leeqwind/HolicPOC>`_ - CVE-2015-2546, CVE-2016-0165, CVE-2016-0167, CVE-2017-0101, CVE-2017-0263, CVE-2018-8120.
- `Jira-Scan <https://github.com/random-robbie/Jira-Scan>`_ - Jira scanner for CVE-2017-9506.
- `Kernel Exploits <https://github.com/bcoles/kernel-exploits>`_ - Various kernel exploits.
- `MS17-010 <https://github.com/worawit/MS17-010>`_ - Exploits for MS17-010.
- `PrintNightmare <https://github.com/afwu/PrintNightmare>`_ - PrintNightmare (CVE-2021-1675) Remote code execution in Windows Spooler Service
- `Qemu-vm-escape <https://github.com/Kira-cxy/qemu-vm-escape>`_ - This is an exploit for CVE-2019-6778, a heap buffer overflow in slirp:tcp_emu().
- `Ruby-advisory-db <https://github.com/rubysec/ruby-advisory-db>`_ - A database of vulnerable Ruby Gems.
- `The Exploit Database <https://github.com/offensive-security/exploit-database>`_ - The official Exploit Database repository.
- `Tpwn <https://github.com/kpwn/tpwn>`_ - Xnu local privilege escalation via cve-2015-???? & cve-2015-???? for 10.10.5, 0day at the time
- `XiphosResearch Exploits <https://github.com/XiphosResearch/exploits>`_ - Miscellaneous proof of concept exploit code written at Xiphos Research for testing purposes.
- `cve-2020-1054 <https://github.com/0xeb-bp/cve-2020-1054>`_ - LPE for CVE-2020-1054 targeting Windows 7 x64

Fuzzing
-------

- `AFL++ <https://github.com/vanhauser-thc/AFLplusplus>`_ - AFL 2.56b with community patches, AFLfast power schedules, qemu 3.1 upgrade + laf-intel support, MOpt mutators, InsTrim instrumentation, unicorn_mode, Redqueen and a lot more.
- `AndroFuzz <https://github.com/jonmetz/AndroFuzz>`_ - A fuzzing utility for Android that focuses on reporting and delivery portions of the fuzzing process.
- `Boofuzz <https://github.com/jtpereyda/boofuzz>`_ - A fork and successor of the Sulley Fuzzing Framework.
- `Construct <http://construct.readthedocs.org>`_ - Declarative data structures for python that allow symmetric parsing and building.
- `Deepstate <https://github.com/trailofbits/deepstate>`_ - A unit test-like interface for fuzzing and symbolic execution.
- `Driller <https://github.com/shellphish/driller>`_ - Augmenting AFL with symbolic execution.
- `Eclipser <https://github.com/SoftSec-KAIST/Eclipser>`_ - Grey-box Concolic Testing on Binary Code.
- `Frankenstein <https://github.com/seemoo-lab/frankenstein>`_ - Broadcom and Cypress firmware emulation for fuzzing and further full-stack debugging.
- `Fusil <http://fusil.readthedocs.io/>`_ - A Python library used to write fuzzing programs. It helps to start process with a prepared environment (limit memory, environment variables, redirect stdout, etc.), start network client or server, and create mangled files.
- `Fuzzbox <https://github.com/iSECPartners/fuzzbox>`_ - A multi-codec media fuzzing tool.
- `Fuzzlyn <https://github.com/jakobbotsch/Fuzzlyn>`_ - Fuzzer for the .NET toolchains, utilizes Roslyn to generate random C# programs.
- `Fuzzotron <https://github.com/denandz/fuzzotron>`_ - A TCP/UDP based network daemon fuzzer.
- `Honggfuzz <http://google.github.io/honggfuzz/>`_ - Security oriented fuzzer with powerful analysis options. Supports evolutionary, feedback-driven fuzzing based on code coverage (sw and hw).
- `InsTrim <https://github.com/csienslab/instrim>`_ - Lightweight Instrumentation for Coverage-guided Fuzzing.
- `KleeFL <https://github.com/julieeen/kleefl>`_ - Seeding Fuzzers With Symbolic Execution.
- `MFFA <https://github.com/fuzzing/MFFA>`_ - Media Fuzzing Framework for Android.
- `Melkor-android <https://github.com/anestisb/melkor-android>`_ - An Android port of the melkor ELF fuzzer.
- `Netzob <https://github.com/netzob/netzob>`_ - Netzob is an opensource tool for reverse engineering, traffic generation and fuzzing of communication protocols.
- `Neuzz <https://github.com/Dongdongshe/neuzz>`_ - A neural-network-assisted fuzzer.
- `OneFuzz <https://github.com/microsoft/onefuzz>`_ - Project OneFuzz enables continuous developer-driven fuzzing to proactively harden software prior to release. With a single command, which can be baked into CICD, developers can launch fuzz jobs from a few virtual machines to thousands of cores.
- `Python-AFL <http://jwilk.net/software/python-afl>`_ - American fuzzy lop fork server and instrumentation for pure-Python code.
- `RPCForge <https://github.com/sogeti-esec-lab/RPCForge>`_ - Windows RPC Python fuzzer.
- `Radamsa-android <https://github.com/anestisb/radamsa-android>`_ - An Android port of radamsa fuzzer.
- `Razzer <https://github.com/compsec-snu/razzer>`_ - A Kernel fuzzer focusing on race bugs.
- `Retrowrite <https://github.com/HexHive/retrowrite>`_ - Retrofitting compiler passes though binary rewriting.
- `SecLists <https://github.com/danielmiessler/SecLists>`_ - A collection of multiple types of lists used during security assessments.
- `Sienna-locomotive <https://github.com/trailofbits/sienna-locomotive>`_ - A user-friendly fuzzing and crash triage tool for Windows.
- `Sulley <https://github.com/OpenRCE/sulley>`_ - Fuzzer development and fuzz testing framework consisting of multiple extensible components.
- `T-Fuzz <https://github.com/HexHive/T-Fuzz>`_ - A fuzzing tool based on program transformation.
- `TAOF <https://sourceforge.net/projects/taof/>`_ - The Art of Fuzzing, including ProxyFuzz, a man-in-the-middle non-deterministic network fuzzer.
- `Unicorefuzz <https://github.com/fgsect/unicorefuzz>`_ - Fuzzing the Kernel Using Unicornafl and AFL++.
- `Unicornafl <https://github.com/AFLplusplus/unicornafl>`_ - Unicorn CPU emulator framework (ARM, AArch64, M68K, Mips, Sparc, X86) adapted to afl++.
- `VUzzer <https://github.com/vusec/vuzzer>`_ - This Project depends heavily on a modeified version of DataTracker, which in turn depends on LibDFT pintool. It has some extra tags added in libdft.
- `Vfuzz <https://github.com/guidovranken/vfuzz>`_ - I don't claim superiority over other engines in performance or efficiency out of the box, but this does implement some features that I felt where lacking elsewhere.
- `Winafl <https://github.com/googleprojectzero/winafl>`_ - A fork of AFL for fuzzing Windows binaries.
- `Winafl_inmemory <https://github.com/s0i37/winafl_inmemory>`_ - WINAFL for blackbox in-memory fuzzing (PIN).
- `Windows IPC Fuzzing Tools <https://www.nccgroup.trust/us/about-us/resources/windows-ipc-fuzzing-tools/>`_ - A collection of tools used to attack applications that use Windows Interprocess Communication mechanisms.
- `Zulu <https://github.com/nccgroup/Zulu.git>`_ - A fuzzer designed for rapid prototyping that normally happens on a client engagement where something needs to be fuzzed within tight timescales.

Info Gathering
--------------

- `ATSCAN <https://github.com/AlisamTechnology/ATSCAN>`_ - Advanced dork Search & Mass Exploit Scanner.
- `Bluto <https://github.com/darryllane/Bluto>`_ - DNS Recon | Brute Forcer | DNS Zone Transfer | DNS Wild Card Checks | DNS Wild Card Brute Forcer | Email Enumeration | Staff Enumeration | Compromised Account Checking
- `Bundler-audit <https://github.com/rubysec/bundler-audit>`_ - Patch-level verification for Bundler.
- `Cloudflare_enum <https://github.com/mandatoryprogrammer/cloudflare_enum>`_ - Cloudflare DNS Enumeration Tool for Pentesters.
- `Commando-vm <https://github.com/fireeye/commando-vm>`_ - Complete Mandiant Offensive VM (Commando VM), the first full Windows-based penetration testing virtual machine distribution. The security community recognizes Kali Linux as the go-to penetration testing platform for those that prefer Linux. Commando VM is for penetration testers that prefer Windows.
- `Dnsenum <https://github.com/fwaeytens/dnsenum/>`_ - A perl script that enumerates DNS information.
- `Dnsmap <https://github.com/makefu/dnsmap/>`_ - Passive DNS network mapper.
- `Dnsrecon <https://github.com/darkoperator/dnsrecon/>`_ - DNS Enumeration Script.
- `Dnsspy <https://github.com/4thel00z/dnsspy>`_ - Performs various DNS enumeration attacks.
- `EgressCheck Framework <https://github.com/stufus/egresscheck-framework>`_ - Used to check for TCP and UDP egress filtering on both windows and unix client systems.
- `Egressbuster <https://github.com/trustedsec/egressbuster>`_ - A method to check egress filtering and identify if ports are allowed. If they are, you can automatically spawn a shell.
- `EyeWitness <https://github.com/FortyNorthSecurity/EyeWitness>`_ - EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.
- `IVRE <https://ivre.rocks>`_ - An open-source framework for network recon. It relies on open-source well-known tools to gather data (network intelligence), stores it in a database, and provides tools to analyze it.
- `Knock <https://github.com/guelfoweb/knock>`_ - A python tool designed to enumerate subdomains on a target domain through a wordlist.
- `Operative-framework <https://github.com/graniet/operative-framework>`_ - This is a framework based on fingerprint action, this tool is used for get information on a website or a enterprise target with multiple modules (Viadeo search,Linkedin search, Reverse email whois, Reverse ip whois, SQL file forensics ...).
- `Recon-ng <https://github.com/lanmaster53/recon-ng>`_ - A full-featured Web Reconnaissance framework written in Python.
- `SMBMap <https://github.com/ShawnDEvans/smbmap>`_ - A handy SMB enumeration tool.
- `SPartan <https://github.com/sensepost/SPartan>`_ - Frontpage and Sharepoint fingerprinting and attack tool.
- `SSLMap <http://thesprawl.org/projects/sslmap/>`_ - TLS/SSL cipher suite scanner.
- `Secretz <https://github.com/lc/secretz>`_ - A tool that minimizes the large attack surface of Travis CI. It automatically fetches repos, builds, and logs for any given organization.
- `Sparty <https://github.com/0xdevalias/sparty>`_ - MS Sharepoint and Frontpage Auditing Tool.
- `Spyse.py <https://github.com/zeropwn/spyse.py>`_ - Python API wrapper and command-line client for the tools hosted on spyse.com.
- `SubFinder <https://github.com/subfinder/subfinder>`_ - A subdomain discovery tool that discovers valid subdomains for websites. Designed as a passive framework to be useful for bug bounties and safe for penetration testing.
- `SubQuest <https://github.com/skepticfx/subquest>`_ - Fast, Elegant subdomain scanner using nodejs.
- `Subbrute <https://github.com/TheRook/subbrute>`_ - A DNS meta-query spider that enumerates DNS records, and subdomains.
- `TravisLeaks <https://github.com/Shashank-In/TravisLeaks>`_ - A tool to find sensitive keys and passwords in Travis logs.
- `TruffleHog <https://github.com/dxa4481/truffleHog>`_ - Searches through git repositories for high entropy strings, digging deep into commit history.
- `URLextractor <https://github.com/eschultze/URLextractor>`_ - Information gathering & website reconnaissance.
- `VHostScan <https://github.com/codingo/VHostScan>`_ - A virtual host scanner that performs reverse lookups, can be used with pivot tools, detect catch-all scenarios, aliases and dynamic default pages.
- `Wmap <https://github.com/MaYaSeVeN/Wmap>`_ - Information gathering for web hacking.
- `XRay <https://github.com/evilsocket/xray>`_ - A tool for recon, mapping and OSINT gathering from public networks.

MITM
----

- `Bettercap <https://bettercap.org/>`_ - A powerful, flexible and portable tool created to perform various types of MITM attacks against a network, manipulate HTTP, HTTPS and TCP traffic in realtime, sniff for credentials and much more.
- `Caplets <https://github.com/bettercap/caplets>`_ - Bettercap scripts (caplets) and proxy modules.
- `Dnsspoof <https://github.com/DanMcInerney/dnsspoof>`_ - DNS spoofer. Drops DNS responses from the router and replaces it with the spoofed DNS response.
- `Ettercap <http://www.ettercap-project.org>`_ - A comprehensive suite for man in the middle attacks. It features sniffing of live connections, content filtering on the fly and many other interesting tricks. It supports active and passive dissection of many protocols and includes many features for network and host analysis.
- `MITMf <https://github.com/byt3bl33d3r/MITMf>`_ - Framework for Man-In-The-Middle attacks.
- `Mallory <https://bitbucket.org/IntrepidusGroup/mallory>`_ - An extensible TCP/UDP man in the middle proxy that is designed to be run as a gateway. Unlike other tools of its kind, Mallory supports modifying non-standard protocols on the fly.
- `Mitmproxy <https://mitmproxy.org/>`_ - An interactive, SSL-capable man-in-the-middle proxy for HTTP with a console interface.
- `Mitmsocks4j <https://github.com/Akdeniz/mitmsocks4j>`_ - Man in the Middle SOCKS Proxy for JAVA.
- `Nogotofail <https://github.com/google/nogotofail>`_ - An on-path blackbox network traffic security testing tool.
- `Responder <https://github.com/SpiderLabs/Responder>`_ - A LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
- `Ssh-mitm <https://github.com/jtesta/ssh-mitm>`_ - An SSH/SFTP man-in-the-middle tool that logs interactive sessions and passwords.

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
- `Keychain-Dumper <https://github.com/ptoomey3/Keychain-Dumper/>`_ - A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken.
- `Mobile Security Framework <http://opensecurity.in>`_ - An intelligent, all-in-one open source mobile application (Android/iOS/Windows) automated pen-testing framework capable of performing static, dynamic analysis and web API testing.
- `Objection <https://github.com/sensepost/objection>`_ - A runtime mobile exploration toolkit, powered by Frida, built to help you assess the security posture of your mobile applications, without needing a jailbreak.
- `QARK <https://github.com/linkedin/qark/>`_ - QARK by LinkedIn is for app developers to scan app for security issues.

Password Cracking
-----------------

- `BozoCrack <https://github.com/juuso/BozoCrack>`_ - A silly & effective MD5 cracker in Ruby.
- `Common-substr <https://github.com/SensePost/common-substr>`_ - Simple awk script to extract the most common substrings from an input text. Built for password cracking.
- `HashCat <https://hashcat.net/hashcat/>`_ - World's fastest and most advanced password recovery utility.
- `Hashcrack <https://github.com/nccgroup/hashcrack>`_ - Guesses hash types, picks some sensible dictionaries and rules for hashcat.
- `Hob0Rules <https://github.com/praetorian-inc/Hob0Rules>`_ - Password cracking rules for Hashcat based on statistics and industry patterns.
- `John the Ripper <http://www.openwall.com/john/>`_ - A fast password cracker.
- `Kwprocessor <https://github.com/hashcat/kwprocessor>`_ - Advanced keyboard-walk generator with configureable basechars, keymap and routes.
- `Mentalist <https://github.com/sc0tfree/mentalist>`_ - A graphical tool for custom wordlist generation. It utilizes common human paradigms for constructing passwords and can output the full wordlist as well as rules compatible with Hashcat and John the Ripper.
- `NPK <https://github.com/Coalfire-Research/npk>`_ - A mostly-serverless distributed hash cracking platform.
- `Patator <https://github.com/lanjelot/patator>`_ - Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.
- `RSMangler <https://github.com/digininja/RSMangler>`_ - It will take a wordlist and perform various manipulations on it similar to those done by John the Ripper with a few extras.
- `THC-Hydra <https://www.thc.org/thc-hydra/>`_ - A very fast network logon cracker which support many different services.

Port Scanning
-------------

- `Angry IP Scanner <http://angryip.org>`_ - Fast and friendly network scanner.
- `Evilscan <https://github.com/eviltik/evilscan>`_ - NodeJS Simple Network Scanner.
- `Flan <https://github.com/cloudflare/flan>`_ - A pretty sweet vulnerability scanner.
- `Masscan <https://github.com/robertdavidgraham/masscan>`_ - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
- `Nmap <https://nmap.org>`_ - Free Security Scanner For Network Exploration & Security Audits.
- `Watchdog <https://github.com/flipkart-incubator/watchdog>`_ - A Comprehensive Security Scanning and a Vulnerability Management Tool.
- `ZGrab <https://github.com/zmap/zgrab2>`_ - Go Application Layer Scanner.
- `Zmap <https://zmap.io>`_ - An open-source network scanner that enables researchers to easily perform Internet-wide network studies. 

Post Exploitation
-----------------

- `3snake <https://github.com/blendin/3snake>`_ - Tool for extracting information from newly spawned processes.
- `Apfell <https://github.com/its-a-feature/Apfell>`_ - A collaborative, multi-platform, red teaming framework.
- `Backdoorme <https://github.com/Kkevsterrr/backdoorme>`_ - Powerful auto-backdooring utility.
- `CatTails <https://github.com/oneNutW0nder/CatTails>`_ - Raw socket library/framework for red team events.
- `Cloudy-kraken <https://github.com/Netflix-Skunkworks/cloudy-kraken>`_ - AWS Red Team Orchestration Framework.
- `Covenant <https://github.com/cobbr/Covenant>`_ - Covenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers.
- `CrackMapExec <https://github.com/byt3bl33d3r/CrackMapExec>`_ - A post-exploitation tool that helps automate assessing the security of large Active Directory networks.
- `CredCrack <https://github.com/gojhonny/CredCrack>`_ - A fast and stealthy credential harvester.
- `Creddump <https://github.com/moyix/creddump>`_ - Dump windows credentials.
- `DBC2 <https://github.com/Arno0x/DBC2>`_ - DropboxC2 is a modular post-exploitation tool, composed of an agent running on the victim's machine, a controler, running on any machine, powershell modules, and Dropbox servers as a means of communication.
- `DET <https://github.com/sensepost/DET>`_ - (extensible) Data Exfiltration Toolkit (DET).
- `DNSlivery <https://github.com/no0be/DNSlivery>`_ - Easy files and payloads delivery over DNS.
- `Dnsteal <https://github.com/m57/dnsteal>`_ - DNS Exfiltration tool for stealthily sending files over DNS requests.
- `Empire <http://www.powershellempire.com>`_ - Empire is a pure PowerShell post-exploitation agent.
- `Enumdb <https://github.com/m8r0wn/enumdb>`_ - MySQL and MSSQL brute force and post exploitation tool to search through databases and extract sensitive information.
- `EvilOSX <https://github.com/Marten4n6/EvilOSX>`_ - A pure python, post-exploitation, RAT (Remote Administration Tool) for macOS / OSX.
- `Fireaway <https://github.com/tcstool/Fireaway>`_ - Next Generation Firewall Audit and Bypass Tool.
- `FruityC2 <https://github.com/xtr4nge/FruityC2>`_ - A post-exploitation (and open source) framework based on the deployment of agents on compromised machines. Agents are managed from a web interface under the control of an operator.
- `GetVulnerableGPO <https://github.com/gpoguy/GetVulnerableGPO.git>`_ - PowerShell script to find 'vulnerable' security-related GPOs that should be hardended.
- `Ghost In The Logs <https://github.com/bats3c/ghost-in-the-logs/>`_ - Evade sysmon and windows event logging.
- `HoneyBadger <https://github.com/trustedsec/HoneyBadger>`_ - A collection of Metasploit modules with a plugin to help automate Post-Exploitation actions on target systems using the Metasploit Framework.
- `HoneypotBuster <https://github.com/JavelinNetworks/HoneypotBuster>`_ - Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host.
- `Iodine <http://code.kryo.se/iodine>`_ - Lets you tunnel IPv4 data through a DNS server.
- `Koadic <https://github.com/zerosum0x0/koadic>`_ - Koadic C3 COM Command & Control - JScript RAT.
- `Mallory <https://github.com/justmao945/mallory>`_ - HTTP/HTTPS proxy over SSH.
- `MicroBackdoor <https://github.com/Cr4sh/MicroBackdoor>`_ - C2 tool for Windows targets with easy customizable code base and small footprint. Micro Backdoor consists from server, client and dropper. It wasn't designed as replacement for your favorite post-exploitation tools but rather as really minimalistic thing with all of the basic features in less than 5000 lines of code.
- `Mimikatz <http://blog.gentilkiwi.com/mimikatz>`_ - A little tool to play with Windows security.
- `Mimikittenz <https://github.com/putterpanda/mimikittenz>`_ - A post-exploitation powershell tool for extracting juicy info from memory.
- `NoPowerShell <https://github.com/bitsadmin/nopowershell>`_ - PowerShell rebuilt in C# for Red Teaming purposes.
- `Orc <https://github.com/zMarch/Orc>`_ - A post-exploitation framework for Linux written in Bash.
- `P0wnedShell <https://github.com/Cn33liz/p0wnedShell>`_ - PowerShell Runspace Post Exploitation Toolkit.
- `PacketWhisper <https://github.com/TryCatchHCF/PacketWhisper>`_ - Stealthily Transfer Data & Defeat Attribution Using DNS Queries & Text-Based Steganography, without the need for attacker-controlled Name Servers or domains; Evade DLP/MLS Devices; Defeat Data- & DNS Name Server Whitelisting Controls. Convert any file type (e.g. executables, Office, Zip, images) into a list of Fully Qualified Domain Names (FQDNs), use DNS queries to transfer data. Simple yet extremely effective.
- `Paragon <https://github.com/KCarretto/paragon>`_ - Red Team engagement platform with the goal of unifying offensive tools behind a simple UI.
- `Pivoter <https://github.com/trustedsec/pivoter>`_ - A proxy tool for pentesters to have easier lateral movement. 
- `Poet <https://github.com/mossberg/poet>`_ - Post-exploitation tool.
- `PoshC2 <https://github.com/nettitude/PoshC2>`_ - A proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement.
- `PowerOPS <https://github.com/fdiskyou/PowerOPS>`_ - PowerShell Runspace Portable Post Exploitation Tool aimed at making Penetration Testing with PowerShell "easier".
- `ProcessHider <https://github.com/M00nRise/ProcessHider>`_ - Post-exploitation tool for hiding processes from monitoring applications.
- `Pupy <https://github.com/n1nj4sec/pupy>`_ - An opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool mainly written in python.
- `Pwnat <https://samy.pl/pwnat/>`_ - Punches holes in firewalls and NATs allowing any numbers of clients behind NATs to directly connect to a server behind a different NAT.
- `Pypykatz <https://github.com/skelsec/pypykatz>`_ - Mimikatz implementation in pure Python.
- `RedGhost <https://github.com/d4rk007/RedGhost>`_ - Linux post exploitation framework written in bash designed to assist red teams in persistence, reconnaissance, privilege escalation and leaving no trace.
- `RemoteRecon <https://github.com/xorrior/RemoteRecon>`_ - Remote Recon and Collection.
- `RottenPotatoNG <https://github.com/breenmachine/RottenPotatoNG>`_ - New version of RottenPotato as a C++ DLL and standalone C++ binary - no need for meterpreter or other tools.
- `Rpc2socks <https://github.com/lexfo/rpc2socks>`_ - Post-exploit tool that enables a SOCKS tunnel via a Windows host using an extensible custom RPC proto over SMB through a named pipe.
- `SafetyKatz <https://github.com/GhostPack/SafetyKatz>`_ - SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's .NET PE Load.
- `Shad0w <https://github.com/bats3c/shad0w>`_ - A post exploitation framework designed to operate covertly on heavily monitored environments.
- `SharpC2 <https://github.com/SharpC2/SharpC2>`_ - .NET Command & Control Framework
- `SocksOverRDP <https://github.com/nccgroup/SocksOverRDP>`_ - Socks5/4/4a Proxy support for Remote Desktop Protocol / Terminal Services.
- `SpYDyishai <https://github.com/Night46/spYDyishai>`_ - A Gmail credential harvester.
- `SprayWMI <https://github.com/trustedsec/spraywmi>`_ - An easy way to get mass shells on systems that support WMI. Much more effective than PSEXEC as it does not leave remnants on a system.
- `Tgcd <http://tgcd.sourceforge.net>`_ - A simple Unix network utility to extend the accessibility of TCP/IP based network services beyond firewalls.
- `TheFatRat <https://github.com/Exploit-install/TheFatRat>`_ - An easy tool to generate backdoor with msfvenom (a part from metasploit framework). This tool compiles a malware with popular payload and then the compiled malware can be execute on windows, android, mac . The malware that created with this tool also have an ability to bypass most AV software protection.
- `WCE <http://www.ampliasecurity.com/research/windows-credentials-editor/>`_ - Windows Credentials Editor (WCE) is a security tool to list logon sessions and add, change, list and delete associated credentials.
- `Weasel <https://github.com/facebookincubator/WEASEL>`_ - DNS covert channel implant for Red Teams.

Reporting
---------

- `Cartography <https://github.com/lyft/cartography>`_ - A Python tool that consolidates infrastructure assets and the relationships between them in an intuitive graph view powered by a Neo4j database.
- `DefectDojo <https://github.com/DefectDojo/django-DefectDojo>`_ - An open-source application vulnerability correlation and security orchestration tool.
- `Dradis <https://dradisframework.com/ce/>`_ - Colllaboration and reporting for IT Security teams.
- `Faraday <http://www.faradaysec.com>`_ - Collaborative Penetration Test and Vulnerability Management Platform.
- `VECTR <https://github.com/SecurityRiskAdvisors/VECTR>`_ - A tool that facilitates tracking of your red and blue team testing activities to measure detection and prevention capabilities across different attack scenarios.

Services
--------

- `SSLyze <https://github.com/nabla-c0d3/sslyze>`_ - SSL configuration scanner.
- `Sslstrip <https://moxie.org/software/sslstrip/>`_ - A demonstration of the HTTPS stripping attacks.
- `Sslstrip2 <https://github.com/LeonardoNve/sslstrip2>`_ - SSLStrip version to defeat HSTS.
- `Tls_prober <https://github.com/WestpointLtd/tls_prober.git>`_ - Fingerprint a server's SSL/TLS implementation.

Training
--------

- `Android-InsecureBankv2 <https://github.com/dineshshetty/Android-InsecureBankv2>`_ - Vulnerable Android application for developers and security enthusiasts to learn about Android insecurities.
- `BadBlood <https://github.com/davidprowe/BadBlood>`_ - Fills a Microsoft Active Directory Domain with a structure and thousands of objects. The output of the tool is a domain similar to a domain in the real world. After BadBlood is ran on a domain, security analysts and engineers can practice using tools to gain an understanding and prescribe to securing Active Directory.
- `DIVA Android <https://github.com/payatu/diva-android>`_ - Damn Insecure and vulnerable App for Android.
- `DVCP-TE <https://github.com/satejnik/DVCP-TE>`_ - Damn Vulnerable Chemical Process - Tennessee Eastman.
- `DVWA <http://dvwa.co.uk>`_ - Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable.
- `DVWS <https://github.com/interference-security/DVWS>`_ - Damn Vulnerable Web Sockets (DVWS) is a vulnerable web application which works on web sockets for client-server communication.
- `Don't Panic <https://github.com/antire-book/dont_panic>`_ - Training linux bind shell with anti-reverse engineering techniques.
- `GRFICS <https://github.com/djformby/GRFICS>`_ - A graphical realism framework for industrial control simulations that uses Unity 3D game engine graphics to lower the barrier to entry for industrial control system security. GRFICS provides users with a full virtual industrial control system (ICS) network to practice common attacks including command injection, man-in-the-middle, and buffer overflows, and visually see the impact of their attacks in the 3D visualization. Users can also practice their defensive skills by properly segmenting the network with strong firewall rules, or writing intrusion detection rules.
- `Hackazon <https://github.com/rapid7/hackazon>`_ - A modern vulnerable web app.
- `Insecure-deserialization-net-poc <https://github.com/omerlh/insecure-deserialisation-net-poc>`_ - A small webserver vulnerable to insecure deserialization.
- `JuliaRT <https://github.com/iknowjason/juliart>`_ - Automated AD Pentest Lab Deployment in the Cloud: IaC Terraform and Ansible Playbook templates for deploying an Active Directory Domain in Azure.
- `Kubernetes Goat <https://github.com/madhuakula/kubernetes-goat>`_ - Designed to be intentionally vulnerable cluster environment to learn and practice Kubernetes security.
- `OWASP Juice Shop <https://www.owasp.org/index.php/OWASP_Juice_Shop_Project>`_ - An intentionally insecure webapp for security trainings written entirely in Javascript which encompasses the entire OWASP Top Ten and other severe security flaws.
- `OWASP NodeGoat <https://www.owasp.org/index.php/Projects/OWASP_Node_js_Goat_Project>`_ - An environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
- `OWASP Railsgoat <http://railsgoat.cktricky.com/>`_ - A vulnerable version of Rails that follows the OWASP Top 10.
- `OWASP Security Shepherd <https://www.owasp.org/index.php/OWASP_Security_Shepherd>`_ - A web and mobile application security training platform.
- `OWASP WebGoat <https://www.owasp.org/index.php/Category:OWASP_WebGoat_Project>`_ - A deliberately insecure Web Application.
- `RopeyTasks <https://github.com/continuumsecurity/RopeyTasks>`_ - Deliberately vulnerable web application.
- `Sadcloud <https://github.com/nccgroup/sadcloud>`_ - A tool for standing up (and tearing down!) purposefully insecure cloud infrastructure.
- `Sqli-labs <https://github.com/Audi-1/sqli-labs>`_ - SQLI labs to test error based, Blind boolean based, Time based.
- `WackoPicko <https://github.com/adamdoupe/WackoPicko>`_ - A vulnerable web application used to test web application vulnerability scanners.
- `Xvwa <https://github.com/s4n7h0/xvwa>`_ - XVWA is a badly coded web application written in PHP/MySQL that helps security enthusiasts to learn application security.

Web
---

- `Arachni <http://www.arachni-scanner.com>`_ - Web Application Security Scanner Framework.
- `Argumentinjectionhammer <https://github.com/nccgroup/argumentinjectionhammer>`_ - A Burp Extension designed to identify argument injection vulnerabilities.
- `Autowasp <https://github.com/GovTech-CSG/Autowasp>`_ - A Burp Suite extension that integrates Burp issues logging, with OWASP Web Security Testing Guide (WSTG), to provide a streamlined web security testing flow for the modern-day penetration tester! This tool will guide new penetration testers to understand the best practices of web application security and automate OWASP WSTG checks.
- `BlackBox Protobuf Burp Extension <https://github.com/nccgroup/blackboxprotobuf>`_ - A Burp Suite extension for decoding and modifying arbitrary protobuf messages without the protobuf type definition.
- `BlindElephant <http://blindelephant.sourceforge.net>`_ - Web Application Fingerprinter.
- `Brosec <https://github.com/gabemarshall/Brosec>`_ - An interactive reference tool to help security professionals utilize useful payloads and commands.
- `Burp Suite <http://portswigger.net/burp/>`_ - An integrated platform for performing security testing of web applications.
- `CloudScraper <https://github.com/jordanpotti/CloudScraper>`_ - Tool to enumerate targets in search of cloud resources. S3 Buckets, Azure Blobs, Digital Ocean Storage Space.
- `Cms-explorer <https://code.google.com/archive/p/cms-explorer/>`_ - CMS Explorer is designed to reveal the the specific modules, plugins, components and themes that various CMS driven web sites are running.
- `Crlfuzz <https://github.com/dwisiswant0/crlfuzz>`_ - A fast tool to scan CRLF vulnerability written in Go.
- `Dirble <https://github.com/nccgroup/dirble>`_ - Fast directory scanning and scraping tool.
- `Dvcs-ripper <https://github.com/kost/dvcs-ripper>`_ - Rip web accessible (distributed) version control systems.
- `Fimap <https://tha-imax.de/git/root/fimap>`_ - Find, prepare, audit, exploit and even google automatically for LFI/RFI bugs.
- `Gobuster <https://github.com/OJ/gobuster>`_ - Directory/file & DNS busting tool written in Go.
- `Jok3r <https://github.com/koutto/jok3r>`_ - Network and Web Pentest Framework.
- `Joomscan <https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project>`_ - Joomla CMS scanner.
- `Jwt_tool <https://github.com/ticarpi/jwt_tool>`_ - A toolkit for testing, tweaking and cracking JSON Web Tokens.
- `Kadabra <https://github.com/D35m0nd142/Kadabra>`_ - Automatic LFI Exploiter and Scanner, written in C++ and a couple extern module in Python.
- `Kadimus <https://github.com/P0cL4bs/Kadimus>`_ - LFI scan and exploit tool.
- `Konan <https://github.com/m4ll0k/Konan>`_ - An advanced open source tool designed to brute force directories and files names on web/application servers.
- `Liffy <https://github.com/hvqzao/liffy>`_ - LFI exploitation tool.
- `LinkFinder <https://github.com/GerbenJavado/LinkFinder>`_ - A python script that finds endpoints in JavaScript files.
- `Netsparker <https://www.netsparker.com>`_ - Web Application Security Scanner.
- `Nikto2 <https://cirt.net/nikto2>`_ - Web application vulnerability scanner.
- `NoSQLMap <http://www.nosqlmap.net>`_ - Automated Mongo database and NoSQL web application exploitation tool.
- `OWASP Xenotix <https://www.owasp.org/index.php/OWASP_Xenotix_XSS_Exploit_Framework>`_ - XSS Exploit Framework is an advanced Cross Site Scripting (XSS) vulnerability detection and exploitation framework.
- `Paros <https://sourceforge.net/projects/paros/>`_ - A Java based HTTP/HTTPS proxy for assessing web application vulnerability.
- `PayloadsAllTheThings <https://github.com/swisskyrepo/PayloadsAllTheThings>`_ - A list of useful payloads and bypass for Web Application Security and Pentest/CTF.
- `Php-jpeg-injector <https://github.com/dlegs/php-jpeg-injector>`_ - Injects php payloads into jpeg images.
- `Pyfiscan <https://github.com/fgeek/pyfiscan>`_ - Free web-application vulnerability and version scanner.
- `Ratproxy <https://code.google.com/archive/p/ratproxy/>`_ - A semi-automated, largely passive web application security audit tool, optimized for an accurate and sensitive detection, and automatic annotation, of potential problems.
- `RecurseBuster <https://github.com/C-Sto/recursebuster>`_ - Rapid content discovery tool for recursively querying webservers, handy in pentesting and web application assessments.
- `Relative-url-extractor <https://github.com/jobertabma/relative-url-extractor>`_ - A small tool that extracts relative URLs from a file.
- `SQLMap <http://sqlmap.org>`_ - Automatic SQL injection and database takeover tool.
- `SQLNinja <http://sqlninja.sourceforge.net/>`_ - SQL Server injection & takeover tool.
- `Scout2 <https://nccgroup.github.io/Scout2/>`_ - Security auditing tool for AWS environments.
- `Skipfish <https://code.google.com/archive/p/skipfish/>`_ - An active web application security reconnaissance tool. It prepares an interactive sitemap for the targeted site by carrying out a recursive crawl and dictionary-based probes.
- `TPLMap <https://github.com/epinna/tplmap>`_ - Automatic Server-Side Template Injection Detection and Exploitation Tool.
- `Tracy <https://github.com/nccgroup/tracy>`_ - A tool designed to assist with finding all sinks and sources of a web application and display these results in a digestible manner.
- `Tsunami <https://github.com/google/tsunami-security-scanner>`_ - General purpose network security scanner with an extensible plugin system for detecting high severity vulnerabilities with high confidence.
- `W3af <http://w3af.org>`_ - Web application attack and audit framework.
- `WPScan <https://wpscan.org>`_ - WPScan is a black box WordPress vulnerability scanner.
- `WPSploit <https://github.com/espreto/wpsploit>`_ - Exploiting Wordpress With Metasploit.
- `WS-Attacker <https://github.com/RUB-NDS/WS-Attacker>`_ - A modular framework for web services penetration testing.
- `WStalker <https://github.com/nccgroup/wstalker>`_ - An easy proxy.
- `Wapiti <http://wapiti.sourceforge.net>`_ - Web application vulnerability scanner.
- `Wappalyzer <https://github.com/AliasIO/Wappalyzer>`_ - Cross-platform utility that uncovers the technologies used on websites.
- `Weevely3 <https://github.com/epinna/weevely3>`_ - Weaponized web shell.
- `Wfuzz <https://github.com/xmendez/wfuzz>`_ - Web application fuzzer.
- `WhatWeb <https://www.morningstarsecurity.com/research/whatweb>`_ - Website Fingerprinter.
- `Wordpress Exploit Framework <https://github.com/rastating/wordpress-exploit-framework>`_ - A Ruby framework for developing and using modules which aid in the penetration testing of WordPress powered websites and systems.
- `Wuzz <https://github.com/asciimoo/wuzz>`_ - Interactive cli tool for HTTP inspection
- `XSS-keylogger <https://github.com/hadynz/xss-keylogger>`_ - A keystroke logger to exploit XSS vulnerabilities in a site.
- `XSS-payload-list <https://github.com/ismailtasdelen/xss-payload-list>`_ - XSS Payload list.
- `XSpear <https://github.com/hahwul/XSpear>`_ - Powerfull XSS Scanning and Parameter analysis tool&gem.
- `Yasuo <https://github.com/0xsauby/yasuo>`_ - A ruby script that scans for vulnerable & exploitable 3rd-party web applications on a network.
- `Zed Attack Proxy (ZAP) <https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project>`_ - The OWASP ZAP core project.

Wireless
--------

- `Aircrack-ng <http://www.aircrack-ng.org>`_ - An 802.11 WEP and WPA-PSK keys cracking program.
- `Airgeddon <https://github.com/v1s1t0r1sh3r3/airgeddon/>`_ - This is a multi-use bash script for Linux systems to audit wireless networks.
- `Kismet <https://kismetwireless.net/>`_ - Wireless network detector, sniffer, and IDS.
- `Krackattacks-scripts <https://github.com/vanhoefm/krackattacks-scripts>`_ - Scripts to test if clients or access points (APs) are affected by the KRACK attack against WPA2.
- `LANs.py <https://github.com/DanMcInerney/LANs.py>`_ - Inject code, jam wifi, and spy on wifi users.
- `Mass-deauth <http://rfkiller.github.io/mass-deauth/>`_ - A script for 802.11 mass-deauthentication.
- `Reaver <https://code.google.com/archive/p/reaver-wps>`_ - Brute force attack against Wifi Protected Setup.
- `Sniffle <https://github.com/nccgroup/Sniffle>`_ - A sniffer for Bluetooth 5 and 4.x (LE) using TI CC1352/CC26x2 hardware.
- `WiFiDuck <https://github.com/spacehuhn/WiFiDuck>`_ - Wireless keystroke injection attack platform.
- `Wifijammer <https://github.com/DanMcInerney/wifijammer>`_ - Continuously jam all wifi clients/routers.
- `Wifikill <https://github.com/roglew/wifikill>`_ - A python program to kick people off of wifi.
- `Wifiphisher <https://github.com/wifiphisher/wifiphisher>`_ - Automated phishing attacks against Wi-Fi networks.
- `Wifite <https://github.com/derv82/wifite>`_ - Automated wireless attack tool.

Reverse Engineering
===================

- `APKiD <https://github.com/rednaga/APKiD>`_ - Android Application Identifier for Packers, Protectors, Obfuscators and Oddities - PEiD for Android.
- `AndBug <https://github.com/swdunlop/AndBug>`_ - A debugger targeting the Android platform's Dalvik virtual machine intended for reverse engineers and developers.
- `Angr <https://github.com/angr/angr>`_ - A platform-agnostic binary analysis framework developed by the Computer Security Lab at UC Santa Barbara and their associated CTF team, Shellphish.
- `AngryGhidra <https://github.com/Nalen98/AngryGhidra>`_ - Angr plugin for Ghidra.
- `Apk2Gold <https://github.com/lxdvs/apk2gold>`_ - Yet another Android decompiler.
- `ApkTool <https://ibotpeaches.github.io/Apktool/>`_ - A tool for reverse engineering Android apk files.
- `Avscript <https://github.com/taviso/avscript>`_ - Avast JavaScript Interactive Shell.
- `B2R2 <https://github.com/B2R2-org/B2R2>`_ - A collection of useful algorithms, functions, and tools for binary analysis.
- `Barf <https://github.com/programa-stic/barf-project>`_ - Binary Analysis and Reverse engineering Framework.
- `BinText <http://www.mcafee.com/kr/downloads/free-tools/bintext.aspx>`_ - A small, very fast and powerful text extractor.
- `BinWalk <https://github.com/devttys0/binwalk>`_ - Analyze, reverse engineer, and extract firmware images.
- `Binaryanalysis-ng <https://github.com/armijnhemel/binaryanalysis-ng>`_ - Binary Analysis Next Generation is a framework for unpacking files (like firmware) recursively and running checks on the unpacked files. Its intended use is to be able to find out the provenance of the unpacked files and classify/label files, making them available for further analysis.
- `Binee <https://github.com/carbonblack/binee>`_ - A complete binary emulation environment that focuses on introspection of all IO operations.
- `Boomerang <https://github.com/BoomerangDecompiler/boomerang>`_ - Decompile x86/SPARC/PowerPC/ST-20 binaries to C.
- `Bytecode-viewer <https://bytecodeviewer.com>`_ - A Java 8 Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More).
- `Bytecode_graph <https://github.com/fireeye/flare-bytecode_graph>`_ - Module designed to modify Python bytecode. Allows instructions to be added or removed from a Python bytecode string.
- `CHIPSEC <https://github.com/chipsec/chipsec>`_ - Platform Security Assessment Framework.
- `Capstone <http://www.capstone-engine.org>`_ - Lightweight multi-platform, multi-architecture disassembly framework with Python bindings.
- `ClassNameDeobfuscator <https://github.com/HamiltonianCycle/ClassNameDeobfuscator>`_ - Simple script to parse through the .smali files produced by apktool and extract the .source annotation lines.
- `Coda <https://github.com/npamnani/coda>`_ - Coredump analyzer.
- `Ctf_import <https://github.com/docileninja/ctf_import>`_ - Run basic functions from stripped binaries cross platform.
- `DBI <https://github.com/s0i37/DBI>`_ - Dynamic Binary Instrumentation plugins.
- `Dex2jar <https://github.com/pxb1988/dex2jar>`_ - Tools to work with android .dex and java .class files.
- `Distorm <https://github.com/gdabah/distorm>`_ - Powerful Disassembler Library For x86/AMD64.
- `DotPeek <https://www.jetbrains.com/decompiler/>`_ - A free-of-charge .NET decompiler from JetBrains.
- `Dotnet-netrace <https://github.com/lowleveldesign/dotnet-netrace>`_ - Collects network traces of .NET applications.
- `Dragondance <https://github.com/0ffffffffh/dragondance>`_ - Binary code coverage visualizer plugin for Ghidra.
- `Dwarf <https://github.com/iGio90/Dwarf>`_ - A gui for mobile reverse engineers, crackers and security analyst. Or damn, what a reversed fluffy or yet, duck warrios are rich as fuck. Whatever you like! Built on top of pyqt5, frida and some terrible code.
- `DynStruct <https://github.com/ampotos/dynStruct>`_ - Reverse engineering tool for automatic structure recovering and memory use analysis based on DynamoRIO and Capstone.
- `EFI DXE Emulator <https://github.com/gdbinit/efi_dxe_emulator>`_ - An EFI DXE phase binaries emulator based on Unicorn.
- `Edb <http://www.codef00.com/projects#debugger>`_ - A cross platform x86/x86-64 debugger.
- `Enjarify <https://github.com/google/enjarify>`_ - A tool for translating Dalvik bytecode to equivalent Java bytecode. This allows Java analysis tools to analyze Android applications.
- `Fibratus <https://github.com/rabbitstack/fibratus>`_ - Tool for exploration and tracing of the Windows kernel.
- `Fino <https://github.com/sysdream/fino>`_ - An Android Dynamic Analysis Tool.
- `Flare-emu <https://github.com/fireeye/flare-emu>`_ - It marries a supported binary analysis framework, such as IDA Pro or Radare2, with Unicorn’s emulation framework to provide the user with an easy to use and flexible interface for scripting emulation tasks. It is designed to handle all the housekeeping of setting up a flexible and robust emulator for its supported architectures so that you can focus on solving your code analysis problems.re
- `Flare-ida <https://github.com/fireeye/flare-ida>`_ - IDA Pro utilities from FLARE team.
- `Frida <https://www.frida.re>`_ - Inject JavaScript to explore native apps on Windows, macOS, Linux, iOS, Android, and QNX.
- `Frida-scripts <https://github.com/interference-security/frida-scripts>`_ - These scripts will help in security research and automation.
- `GEF <https://gef.readthedocs.io/en/latest/>`_ - Multi-Architecture GDB Enhanced Features for Exploiters & Reverse-Engineers.
- `Gdb-dashboard <https://github.com/cyrus-and/gdb-dashboard>`_ - Modular visual interface for GDB in Python.
- `Gdbstub <https://github.com/mborgerson/gdbstub>`_ - A simple, dependency-free GDB stub that can be easily dropped in to your project.
- `Ghidra <https://github.com/NationalSecurityAgency/ghidra>`_ - A software reverse engineering (SRE) framework.
- `Ghidra_kernelcache <https://github.com/0x36/ghidra_kernelcache>`_ - A Ghidra framework for iOS kernelcache reverse engineering.
- `Ghidra_scripts <https://github.com/ghidraninja/ghidra_scripts>`_ - Scripts for the Ghidra software reverse engineering suite.
- `Golang_loader_assist <https://github.com/strazzere/golang_loader_assist>`_ - Making GO reversing easier in IDA Pro.
- `Granary <https://github.com/Granary/granary>`_ - A  kernel space dynamic binary translation framework. The main goal of Granary is to enable flexible and efficient instrumentation of Linux kernel modules, while imposing no overhead to non-module kernel code.
- `Grap <https://github.com/QuoSecGmbH/grap>`_ - Define and match graph patterns within binaries.
- `HVMI <https://github.com/hvmi/hvmi>`_ - Hypervisor Memory Introspection Core Library.
- `Haybale <https://github.com/PLSysSec/haybale>`_ - Symbolic execution of LLVM IR with an engine written in Rust.
- `Heap-viewer <https://github.com/danigargu/heap-viewer>`_ - An IDA Pro plugin to examine the glibc heap, focused on exploit development.
- `HexRaysCodeXplorer <https://github.com/REhints/HexRaysCodeXplorer>`_ - Hex-Rays Decompiler plugin for better code navigation
- `Hopper <https://www.hopperapp.com>`_ - A OS X and Linux Disassembler/Decompiler for 32/64 bit Windows/Mac/Linux/iOS executables.
- `ICSREF <https://github.com/momalab/ICSREF>`_ - A tool for reverse engineering industrial control systems binaries.
- `IDA Free <https://www.hex-rays.com/products/ida/support/download_freeware.shtml>`_ - The freeware version of IDA.
- `IDA Patcher <https://github.com/iphelix/ida-patcher>`_ - IDA Patcher is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's ability to patch binary files and memory.
- `IDA Pomidor <http://thesprawl.org/projects/ida-pomidor/>`_ - IDA Pomidor is a plugin for Hex-Ray's IDA Pro disassembler that will help you retain concentration and productivity during long reversing sessions.
- `IDA Pro <https://www.hex-rays.com/products/ida/index.shtml>`_ - A Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger.
- `IDA Sploiter <http://thesprawl.org/projects/ida-sploiter/>`_ - IDA Sploiter is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's capabilities as an exploit development and vulnerability research tool.
- `IDAPython <https://github.com/idapython/>`_ - An IDA plugin which makes it possible to write scripts for IDA in the Python programming language. 
- `IDAwasm <https://github.com/fireeye/idawasm>`_ - IDA Pro loader and processor modules for WebAssembly.
- `IRPMon <https://github.com/MartinDrab/IRPMon>`_ - The goal of the tool is to monitor requests received by selected device objects or kernel drivers. The tool is quite similar to IrpTracker but has several enhancements. It supports 64-bit versions of Windows (no inline hooks are used, only modifications to driver object structures are performed) and monitors IRP, FastIo, AddDevice, DriverUnload and StartIo requests.
- `Idaemu <https://github.com/36hours/idaemu>`_ - Is an IDA Pro Plugin, use for emulating code in IDA Pro.
- `Immunity Debugger <http://debugger.immunityinc.com/>`_ - A powerful new way to write exploits and analyze malware.
- `JAD <http://varaneckas.com/jad/>`_ - JAD Java Decompiler.
- `JD-GUI <http://jd.benow.ca>`_ - Aims to develop tools in order to decompile and analyze Java 5 “byte code” and the later versions.
- `Jadx <https://github.com/skylot/jadx>`_ - Decompile Android files.
- `Keystone Engine <http://www.keystone-engine.org>`_ - A lightweight multi-platform, multi-architecture assembler framework.
- `Krakatau <https://github.com/Storyyeller/Krakatau>`_ - Java decompiler, assembler, and disassembler.
- `Levitate <https://github.com/levitateplatform/levitate>`_ - Reverse Engineering and Static Malware Analysis Platform.
- `MARA Framework <https://github.com/xtiankisutsa/MARA_Framework>`_ - A Mobile Application Reverse engineering and Analysis Framework.
- `Manticore <https://github.com/trailofbits/manticore>`_ - Prototyping tool for dynamic binary analysis, with support for symbolic execution, taint analysis, and binary instrumentation.
- `Medusa <https://github.com/wisk/medusa>`_ - A disassembler designed to be both modular and interactive.
- `MegaDumper <https://github.com/CodeCracker-Tools/MegaDumper>`_ - Dump native and .NET assemblies.
- `Minhook <https://github.com/TsudaKageyu/minhook>`_ - The Minimalistic x86/x64 API Hooking Library for Windows.
- `Mona.py <https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/>`_ - PyCommand for Immunity Debugger that replaces and improves on pvefindaddr.
- `OllyDbg <http://www.ollydbg.de>`_ - An x86 debugger that emphasizes binary code analysis.
- `PEDA <https://github.com/longld/peda>`_ - Python Exploit Development Assistance for GDB.
- `Paimei <https://github.com/OpenRCE/paimei>`_ - Reverse engineering framework, includes PyDBG, PIDA, pGRAPH.
- `Pigaios <https://github.com/joxeankoret/pigaios>`_ - A tool for matching and diffing source codes directly against binaries.
- `Plasma <https://github.com/joelpx/plasma>`_ - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code.
- `Ponce <https://github.com/illera88/Ponce>`_ - An IDA Pro plugin that provides users the ability to perform taint analysis and symbolic execution over binaries in an easy and intuitive fashion. With Ponce you are one click away from getting all the power from cutting edge symbolic execution. Entirely written in C/C++.
- `Procyon <https://bitbucket.org/mstrobel/procyon>`_ - A modern open-source Java decompiler.
- `Protobuf-inspector <https://github.com/jmendeth/protobuf-inspector>`_ - Tool to reverse-engineer Protocol Buffers with unknown definition.
- `Pwndbg <https://github.com/pwndbg/pwndbg>`_ - Exploit Development and Reverse Engineering with GDB Made Easy.
- `Pyew <https://github.com/joxeankoret/pyew>`_ - Command line hexadecimal editor and disassembler, mainly to analyze malware.
- `QBDI <https://github.com/QBDI/QBDI>`_ - A Dynamic Binary Instrumentation framework based on LLVM.
- `Qira <http://qira.me>`_ - QEMU Interactive Runtime Analyser.
- `R2MSDN <https://github.com/newlog/r2msdn>`_ - R2 plugin to add MSDN documentation URLs and parameter names to imported function calls.
- `RABCDAsm <https://github.com/CyberShadow/RABCDAsm>`_ - Robust ABC (ActionScript Bytecode) [Dis-]Assembler.
- `Radare2 <http://www.radare.org>`_ - Opensource, crossplatform reverse engineering framework.
- `Radare2-bindings <https://github.com/radare/radare2-bindings>`_ - Bindings of the r2 api for Valabind and friends.
- `Redexer <https://github.com/plum-umd/redexer>`_ - A reengineering tool that manipulates Android app binaries.
- `Rizin <https://github.com/rizinorg/rizin>`_ - A fork of the radare2 reverse engineering framework with a focus on usability, working features and code cleanliness.
- `ScratchABit <https://github.com/pfalcon/ScratchABit>`_ - Easily retargetable and hackable interactive disassembler with IDAPython-compatible plugin API.
- `Shed <https://github.com/enkomio/shed>`_ - .NET runtime inspector.
- `Simplify <https://github.com/CalebFenton/simplify>`_ - Generic Android Deobfuscator.
- `SimplifyGraph <https://github.com/fireeye/SimplifyGraph>`_ - IDA Pro plugin to assist with complex graphs.
- `Smali <https://github.com/JesusFreke/smali>`_ - Smali/baksmali is an assembler/disassembler for the dex format used by dalvik, Android's Java VM implementation.
- `Sojobo <https://github.com/enkomio/Sojobo>`_ - An emulator for the B2R2 framework. It was created to easier the analysis of potentially malicious files. It is totally developed in .NET so you don't need to install or compile any other external libraries.
- `Swiffas <https://github.com/ahixon/swiffas>`_ - SWF parser and AVM2 (Actionscript 3) bytecode parser.
- `Swift-frida <https://github.com/maltek/swift-frida>`_ - Frida library for interacting with Swift programs.
- `Toolbag <https://github.com/aaronportnoy/toolbag>`_ - The IDA Toolbag is a plugin providing supplemental functionality to Hex-Rays IDA Pro disassembler.
- `Triton <https://github.com/JonathanSalwan/Triton>`_ - Triton is a Dynamic Binary Analysis (DBA) framework. It provides internal components like a Dynamic Symbolic Execution (DSE) engine, a dynamic taint engine, AST representations of the x86, x86-64, ARM32 and AArch64 Instructions Set Architecture (ISA), SMT simplification passes, an SMT solver interface and, the last but not least, Python bindings.
- `UPX <https://upx.github.io>`_ - The Ultimate Packer for eXecutables.
- `Ufgraph <https://github.com/bfosterjr/ufgraph>`_ - A simple script which parses the output of the uf (un-assemble function) command in windbg and uses graphviz to generate a control flow graph as a PNG/SVG/PDF/GIF (see -of option) and displays it.
- `Uncompyle <https://github.com/gstarnberger/uncompyle>`_ - Decompile Python 2.7 binaries (.pyc).
- `Unicorn Engine <http://www.unicorn-engine.org>`_ - A lightweight, multi-platform, multi-architecture CPU emulator framework based on QEMU.
- `Unlinker <https://github.com/jonwil/unlinker>`_ - Unlinker is a tool that can rip functions out of Visual C++ compiled binaries and produce Visual C++ COFF object files.
- `VMX_INTRINSICS <https://github.com/synacktiv/vmx_intrinsics>`_ - VMX intrinsics plugin for Hex-Rays decompiler.
- `VT-IDA Plugin <https://github.com/VirusTotal/vt-ida-plugin>`_ - Official VirusTotal plugin for IDA Pro.
- `Voltron <https://github.com/snare/voltron>`_ - An extensible debugger UI toolkit written in Python. It aims to improve the user experience of various debuggers (LLDB, GDB, VDB and WinDbg) by enabling the attachment of utility views that can retrieve and display data from the debugger host.
- `WinDbg <https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit>`_ - Windows Driver Kit and WinDbg.
- `WinHex <http://www.winhex.com/winhex/>`_ - A hexadecimal editor, helpful in the realm of computer forensics, data recovery, low-level data processing, and IT security.
- `WinIPT <https://github.com/ionescu007/winipt>`_ - The Windows Library for Intel Process Trace (WinIPT) is a project that leverages the new Intel Processor Trace functionality exposed by Windows 10 Redstone 5 (1809), through a set of libraries and a command-line tool.
- `X64_dbg <http://x64dbg.com>`_ - An open-source x64/x32 debugger for windows.
- `Xxxswf <https://bitbucket.org/Alexander_Hanel/xxxswf>`_ - A Python script for analyzing Flash files.
- `YaCo <https://github.com/DGA-MI-SSI/YaCo>`_ - An Hex-Rays IDA plugin. When enabled, multiple users can work simultaneously on the same binary. Any modification done by any user is synchronized through git version control.
- `uEmu <https://github.com/alexhude/uEmu>`_ - Tiny cute emulator plugin for IDA based on unicorn.

Security
========

Asset Management
----------------

Cloud Security
--------------

- `Aws-nuke <https://github.com/rebuy-de/aws-nuke>`_ - Nuke a whole AWS account and delete all its resources.
- `Azucar <https://github.com/nccgroup/azucar/>`_ - Security auditing tool for Azure environments.
- `CloudMapper <https://github.com/duo-labs/cloudmapper>`_ - CloudMapper helps you analyze your Amazon Web Services (AWS) environments.
- `Hammer <https://github.com/dowjones/hammer>`_ - Dow Jones Hammer : Protect the cloud with the power of the cloud(AWS).
- `IAMFinder <https://github.com/prisma-cloud/IAMFinder>`_ - Enumerates and finds users and IAM roles in a target AWS account. With only the AWS account number of the targeted account, IAMFinder is able to identify users and roles in that environment. Upon successfully identifying an IAM role, IAMFinder can also check if this role can be assumed anonymously.
- `Panther <https://runpanther.io>`_ - A Cloud-Native SIEM for the Modern Security Team
- `Parliament <https://github.com/duo-labs/parliament>`_ - An AWS IAM linting library. It reviews policies looking for problems.
- `Patrolaroid <https://github.com/rpetrich/patrolaroid>`_ - An instant camera for capturing cloud workload risks. It’s a prod-friendly scanner that makes finding security issues in AWS instances and buckets less annoying and disruptive for software engineers and cloud admins.
- `Security Monkey <https://github.com/Netflix/security_monkey>`_ - Security Monkey monitors AWS, GCP, OpenStack, and GitHub orgs for assets and their changes over time.
- `Varna <https://github.com/endgameinc/varna>`_ - Quick & Cheap AWS CloudTrail Monitoring with Event Query Language (EQL)
Resources
- `s3cr3t <https://github.com/axl89/s3cr3t>`_ - Serve files securely from an S3 bucket with expiring links and other restrictions.

DevOps
------

- `Trivy <https://github.com/aquasecurity/trivy>`_ - A simple and comprehensive vulnerability scanner for containers and other artifacts. A software vulnerability is a glitch, flaw, or weakness present in the software or in an Operating System. Trivy detects vulnerabilities of OS packages (Alpine, RHEL, CentOS, etc.) and application dependencies (Bundler, Composer, npm, yarn, etc.). Trivy is easy to use.

Endpoint Security
-----------------

- `AIDE <https://aide.github.io>`_ - Advanced Intrusion Detection Environment is a file and directory integrity checker.
- `Duckhunt <https://github.com/pmsosa/duckhunt>`_ - Prevent RubberDucky (or other keystroke injection) attacks.
- `Hardentools <https://github.com/securitywithoutborders/hardentools>`_ - A utility that disables a number of risky Windows features.
- `Lynis <https://github.com/CISOfy/lynis>`_ - Security auditing tool for Linux, macOS, and UNIX-based systems. Assists with compliance testing (HIPAA/ISO27001/PCI DSS) and system hardening. Agentless, and installation optional.
- `OpenEDR <https://github.com/ComodoSecurity/openedr>`_ - A full blown EDR capability. It is one of the most sophisticated, effective EDR code base in the world and with the community’s help it will become even better.
- `Osx-config-check <https://github.com/kristovatlas/osx-config-check>`_ - Verify the configuration of your OS X machine.
- `ProcMon-for-Linux <https://github.com/microsoft/ProcMon-for-Linux>`_ - A Linux reimagining of the classic Procmon tool from the Sysinternals suite of tools for Windows. Procmon provides a convenient and efficient way for Linux developers to trace the syscall activity on the system.
- `Xnumon <https://github.com/droe/xnumon>`_ - Monitor macOS for malicious activity.

Network Security
----------------

- `AdGuardHome <https://github.com/AdguardTeam/AdGuardHome>`_ - Network-wide ads & trackers blocking DNS server.
- `EveBox <https://github.com/jasonish/evebox>`_ - A web based Suricata "eve" event viewer for Elastic Search.
- `Pi-hole <https://github.com/pi-hole/pi-hole>`_ - A DNS sinkhole that protects your devices from unwanted content, without installing any client-side software.
- `Scirius <https://github.com/StamusNetworks/scirius/>`_ - A web application for Suricata ruleset management.

Orchestration
-------------

- `Stoq <https://stoq.punchcyber.com/>`_ - An open source framework for enterprise level automated analysis.

Phishing
--------

- `Miteru <https://github.com/ninoseki/miteru>`_ - An experimental phishing kit detection tool.
- `StreamingPhish <https://github.com/wesleyraptor/streamingphish>`_ - Python-based utility that uses supervised machine learning to detect phishing domains from the Certificate Transparency log network.

Privacy
-------

- `Git-crypt <https://github.com/AGWA/git-crypt>`_ - Transparent file encryption in git.
- `GoSecure <https://iadgov.github.io/goSecure/>`_ - An easy to use and portable Virtual Private Network (VPN) system built with Linux and a Raspberry Pi.
- `I2P <https://geti2p.net>`_ - The Invisible Internet Project.
- `Nipe <https://github.com/GouveaHeitor/nipe>`_ - A script to make Tor Network your default gateway.
- `SecureDrop <https://freedom.press/securedrop>`_ - Open-source whistleblower submission system that media organizations can use to securely accept documents from and communicate with anonymous sources.
- `Sshuttle <https://github.com/sshuttle/sshuttle>`_ - Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling. 
- `Tomb <https://github.com/dyne/Tomb>`_ - A minimalistic commandline tool to manage encrypted volumes aka The Crypto Undertaker.
- `Tor <https://www.torproject.org>`_ - The free software for enabling onion routing online anonymity.
- `Toriptables2 <https://github.com/ruped24/toriptables2>`_ - A python script alternative to Nipe. Makes Tor Network your default gateway.

Social Engineering
==================

Framework
---------

- `SET <https://github.com/trustedsec/social-engineer-toolkit>`_ - The Social-Engineer Toolkit from TrustedSec.

Harvester
---------

- `Creepy <http://www.geocreepy.com>`_ - A geolocation OSINT tool.
- `Datasploit <https://github.com/dvopsway/datasploit>`_ - A tool to perform various OSINT techniques, aggregate all the raw data, visualise it on a dashboard, and facilitate alerting and monitoring on the data.
- `Email-enum <https://github.com/fuckup1337/email-enum>`_ - Searches mainstream websites and tells you if an email is registered.
- `Github-dorks <https://github.com/techgaun/github-dorks>`_ - CLI tool to scan github repos/organizations for potential sensitive information leak.
- `Maltego <https://www.paterva.com>`_ - Proprietary software for open source intelligence and forensics, from Paterva.
- `Metagoofil <https://github.com/laramies/metagoofil>`_ - Metadata harvester.
- `SpiderFoot <http://www.spiderfoot.net>`_ - Automates OSINT collection so that you can focus on analysis.
- `TTSL <https://github.com/dchrastil/TTSL>`_ - Tool to scrape LinkedIn.
- `TheHarvester <http://www.edge-security.com/theharvester.php>`_ - E-mail, subdomain and people names harvester.

Phishing
--------

- `BlackPhish <https://github.com/iinc0gnit0/BlackPhish>`_ - Super lightweight with many features and blazing fast speeds.
- `Blackeye <https://github.com/thelinuxchoice/blackeye>`_ - The most complete Phishing Tool, with 32 templates +1 customizable.
- `CredSniper <https://github.com/ustayready/CredSniper>`_ - A phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens.
- `FiercePhish <https://github.com/Raikia/FiercePhish>`_ - A full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns, schedule sending of emails, and much more.
- `GoPhish <https://github.com/gophish/gophish>`_ - Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
- `Lockphish <https://github.com/thelinuxchoice/lockphish>`_ - Lockphish it's the first tool for phishing attacks on the lock screen, designed to grab Windows credentials, Android PIN and iPhone Passcode using a https link.
- `Modlishka <https://github.com/drk1wi/Modlishka>`_ - Reverse Proxy. Phishing NG.
- `Muraena <https://github.com/muraenateam/muraena>`_ - An almost-transparent reverse proxy aimed at automating phishing and post-phishing activities.
- `Phishing-frenzy <https://github.com/pentestgeek/phishing-frenzy>`_ - Ruby on Rails Phishing Framework.
- `Pompa <https://github.com/m1nl/pompa>`_ - Fully-featured spear-phishing toolkit - web front-end.
- `Whatsapp-phishing <https://github.com/Ignitetch/whatsapp-phishing>`_ - The best tool for whatsapp-phishing with otp provider.

Wardialing
----------

- `Voipwardialer <https://github.com/x25today/voipwardialer>`_ - A Voip Wardialer for the phreaking of 2020.

