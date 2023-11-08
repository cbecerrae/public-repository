# Module 2: Linux Overview
[Course: Operating Systems Basics](https://skillsforall.com/course/operating-systems-basics)

## 2.0. Introduction

### 2.0.1 Why Should I Take this Module?
Linux is an open-source operating system that is fast, powerful, and highly customizable. It is built for network use as either a client or server.

### 2.0.2 What Will I Learn in this Module?
| Topic Title                   | Topic Objective                                          |
| ----------------------------- | -------------------------------------------------------- |
| Linux Basics                  | Explain why Linux skills are essential for network security monitoring and investigation. |
| Working in the Linux Shell    | Use the Linux shell to manipulate text files.            |
| Linux Servers and Clients     | Use the Linux command line to identify servers that are running on a computer. |
| Basic Server Administration   | Use commands to locate and monitor log files.            |
| The Linux File System         | Use commands to manage the Linux file system and permissions. |
| Working in the Linux GUI      | Explain the basic components of the Linux GUI.           |
| Working on a Linux Host       | Use tools to detect malware on a Linux host.             |


### 2.0.3 Lab Video - Install a Virtual Machine on a Personal Computer
Computing power and resources have increased tremendously over the last 10 years. A benefit of having multicore processors and large amounts of RAM is the ability to use virtualization. With virtualization, one or more virtual computers can operate inside a single physical computer. Virtual computers that run within physical computers are called virtual machines. Virtual machines are often called guests, and physical computers are often called hosts. Anyone with a modern computer and operating system can run virtual machines.

### 2.0.4 Lab - Install a Virtual Machine on a Personal Computer
```shell
$ ip address # protocol address management
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:3d:bf:6b brd ff:ff:ff:ff:ff:ff
    inet 192.168.2.5/24 metric 100 brd 192.168.2.255 scope global dynamic enp0s3
       valid_lft 42628sec preferred_lft 42628sec
    inet6 fe80::a00:27ff:fe3d:bf6b/64 scope link 
       valid_lft forever preferred_lft forever
# The loopback interface is assigned 127.0.0.1/8, and the Ethernet interface is assigned an IP address in the 192.168.2.5/24 network.
```

## 2.1. Linux Basics

### 2.1.1 What is Linux?
Linux is an operating system that was created in 1991. Linux is open source, fast, reliable, and small. It requires very little hardware resources to run and is highly customizable.  Linux was created, and is currently maintained, by a community of programmers.

Linux is designed to be connected to the network, which makes it much simpler to write and use network-based applications. Because Linux is open source, any person or company can get the kernel’s source code, inspect it, modify it, and re-compile it at will. 

A Linux distribution is the term used to describe packages created by different organizations. Linux distributions (or distros) include the Linux kernel with customized tools and software packages.

### 2.1.2 The Value of Linux
- Linux is open source - Any person can acquire Linux at no charge and modify it to fit specific needs. This flexibility allows analysts and administrators to tailor-build an operating system specifically for security analysis.
- The Linux CLI is very powerful - While a GUI makes many tasks easier to perform, it adds complexity and requires more computer resources to run. The Linux Command Line Interface (CLI) is extremely powerful and enables analysts to perform tasks not only directly on a terminal, but also remotely.
- The user has more control over the OS - The administrator user in Linux, known as the root user, or superuser, has absolute power over the computer. Unlike other operating systems, the root user can modify any aspect of the computer with a few keystrokes. This ability is especially valuable when working with low level functions such as the network stack. It allows the root user to have precise control over the way network packets are handled by the operating system.
- It allows for better network communication control - Control is an inherent part of Linux. Because the OS can be adjusted in practically every aspect, it is a great platform for creating network applications. This is the same reason that many great network-based software tools are available for Linux only.

### 2.1.3 Linux in the SOC
The flexibility provided by Linux is a great feature for the Security Operations Center (SOC). The entire operating system can be tailored to become the perfect security analysis platform. For example, administrators can add only the necessary packages to the OS, making it lean and efficient. Specific software tools can be installed and configured to work in conjunction, allowing administrators to build a customized computer that fits perfectly in the workflow of a SOC.

Sguil is the cybersecurity analyst console in a special version of Linux called Security Onion. Security Onion is an open source suite of tools that work together for network security analysis.

### 2.1.4 Linux Tools
#### Network packet capture software
- A crucial tool for a SOC analyst as it makes it possible to observe and understand every detail of a network transaction.
- Wireshark is a popular packet capture tool.
#### Malware analysis tools
- These tools allow analysts to safely run and observe malware execution without the risk of compromising the underlying system.
#### Intrusion detection systems (IDSs)
- These tools are used for real-time traffic monitoring and inspection.
- If any aspect of the currently flowing traffic matches any of the established rules, a pre-defined action is taken.
#### Firewalls
- This software is used to specify, based on pre-defined rules, whether traffic is allowed to enter or leave a network or device.
#### Log managers
- Log files are used to record events.
- Because a network can generate a very large number of log entries, log manager software is employed to facilitate log monitoring.
#### Security information and event management (SIEM)
- SIEMs provide real-time analysis of alerts and log entries generated by network appliances such as IDSs and firewalls.
#### Ticketing systems
- Task ticket assignment, editing, and recording is done through a ticket management system. Security alerts are often assigned to analysts through a ticketing system.

In addition to SOC-specific tools, Linux computers that are used in the SOC often contain penetration testing tools. Also known as PenTesting, a penetration test is the process of looking for vulnerabilities in a network or computer by attacking it. Packet generators, port scanners, and proof-of-concept exploits are examples of PenTesting tools.

Kali Linux is a Linux distribution groups many penetration tools together in a single Linux distribution.

## 2.2. Working in the Linux Shell

### 2.2.1 The Linux Shell
In Linux, the user communicates with the OS by using the CLI or the GUI. Linux often starts in the GUI by default. One way to access the CLI from the GUI is through a terminal emulator application. These applications provide user access to the CLI and are often named as some variation of the word “terminal”. In Linux, popular terminal emulators are Terminator, eterm, xterm, konsole, and gnome-terminal.

Note: The terms shell, console, console window, CLI terminal, and terminal window are often used interchangeably.

### 2.2.2 Basic Commands
Linux commands are programs created to perform a specific task.

Because commands are programs stored on the disk, when a user types a command, the shell must find it on the disk before it can be executed. The shell will look for user-typed commands in specific directories and attempt to execute them. The list of directories checked by the shell is called the path. The path contains many directories commonly used to store commands. If a command is not in the path, the user must specify its location, or the shell will not be able to find it. Users can easily add directories to the path, if necessary.

To invoke a command via the shell, simply type its name. The shell will try to find it in the system path and execute it.

| Command    | Description                                                       |
|------------|-------------------------------------------------------------------|
| mv         | Moves or renames files and directories                            |
| chmod      | Modifies file permissions                                         |
| chown      | Changes the ownership of a file                                   |
| dd         | Copies data from an input to an output                            |
| pwd        | Displays the name of the current directory                        |
| ps         | Lists the processes that are currently running in the system      |
| su         | Simulates a login as another user or to become a superuser        |
| sudo       | Runs a command as a super user, by default, or another named user |
| grep       | Used to search for specific strings of characters within a file or other command outputs. To search through the output of a previous command, `grep` must be piped at the end of the previous command. |
| ifconfig   | Used to display or configure network card related information. If issued without parameters, `ifconfig` will display the current network card(s) configuration. Note: While still widely in use, this command is deprecated. Use `ip address` instead. |
| apt-get    | Used to install, configure and remove packages on Debian and its derivatives. Note: `apt-get` is a user-friendly command line front-end for `dpkg`, Debian’s package manager. The combo `dpkg` and `apt-get` is the default package manager system in all Debian Linux derivatives, including Raspbian. |
| iwconfig   | Used to display or configure wireless network card related information. Similar to `ifconfig`, `iwconfig` will display wireless information when issued without parameters. |
| shutdown   | Shuts down the system, `shutdown` can be instructed to perform a number of shut down related tasks, including restart, halt, put to sleep or kick out all currently connected users. |
| passwd     | Used to change the password. If no parameters are provided, `passwd` changes the password for the current user. |
| cat        | Used to list the contents of a file and expects the file name as the parameter. The `cat` command is usually used on text files. |
| man        | Used to display the documentation for a specific command. |

### 2.2.3 File and Directory Commands
Many command line tools are included in Linux by default. To adjust the command operation, users can pass parameters and switches along with the command.

| Command    | Description                                                    |
|------------|----------------------------------------------------------------|
| ls         | Displays the files inside a directory                          |
| cd         | Changes the current directory                                  |
| mkdir      | Creates a directory under the current directory                |
| cp         | Copies files from source to destination                        |
| mv         | Moves or renames files and directories                          |
| rm         | Removes files                                                 |
| grep       | Searches for specific strings of characters within a file or other commands outputs |
| cat        | Lists the contents of a file and expects the file name as the parameter |

### 2.2.4 Working with Text Files
Linux has many different text editors, with various features and functions. Some text editors include graphical interfaces while others are command-line only tools. Each text editor includes a feature set designed to support a specific type of task. Some text editors focus on the programmer and include features such as syntax highlighting, bracket and parenthesis check and matching, find and replace, multi-line Regex support, spell check, and other programming-focused features.

While graphical text editors are convenient and easy to use, command line-based text editors are very important for Linux users. The main benefit of command-line-based text editors is that they allow for text file editing from a remote computer.

Consider the following scenario: a user must perform administrative tasks on a Linux computer but is not sitting in front of that computer. Using SSH, the user starts a remote shell to the remote computer. Under the text-based remote shell, the graphical interface is not available, which makes it impossible to rely on tools such as graphical text editors. In this type of situation, text-based programs are crucial.

### 2.2.5 The Importance of Text Files in Linux
In Linux, everything is treated as a file. This includes the memory, the disks, the monitor, and the directories. For example, from the operating system standpoint, showing information on the display means to write to the file that represents the display device. It should be no surprise that the computer itself is configured through files. Known as configuration files, they are usually text files used to store adjustments and settings for specific applications or services. Practically everything in Linux relies on configuration files to work. Some services have not one, but several configuration files.

Users with proper permission levels can use text editors to change the contents of configuration files. After the changes are made, the file is saved and can be used by the related service or application. Users are able to specify exactly how they want any given application or service to behave. When launched, services and applications check the contents of specific configuration files to adjust their behavior accordingly.

### 2.2.6 Lab - Working with Text Files in the CLI

#### Part 1: Graphical Text Editors
SciTE is a simple, small and fast graphical text editor. It does not have many advanced features.

```shell
$ scite .txt # Launchs SciTE text editor in the GUI 
```

#### Part 2: Command Line Text Editors
Nano is a popular command-line text editor. Text editors are often used for system configuration and maintenance in Linux.

Due to the lack of graphical support, nano (or GNU nano) can only be controlled with the keyboard. For example, CTRL+O saves the current file; CTRL+W opens the search menu. GNU nano uses a two-line shortcut bar at the bottom of the screen, where commands for the current context are listed. Press CTRL+G for the help screen and a complete list of commands.

```shell
$ nano .txt # Launchs Nano text editor in the CLI    
```

Note: Another extremely popular text editor is called Vim. While the learning curve for Vim is considered steep, Vim is a very powerful command line-based text editor. It is included by default in almost all Linux distributions.

#### Part 3: Working with Configuration Files
The program author defines the location of configuration for a given program (service or application). Because of that, the documentation should be consulted when assessing the location of the configuration file. Conventionally however, in Linux, configuration files that are used to configure user applications are often placed in the user’s home directory while configuration files used to control system-wide services are placed in the /etc directory. Users always have permission to write to their own home directories and are able to configure the behavior of applications they use.

While configuration files related to user applications are conventionally placed under the user’s home directory, configuration files relating to system-wide services are place in the /etc directory, by convention. Web services, print services, ftp services, and email services are examples of services that affect the entire system and of which configuration files are stored under /etc. Notice that regular users do not have writing access to /etc. This is important as it restricts the ability to change the system-wide service configuration to the root user only.

System-wide configuration files are not very different from the user-application files. nginx is a lightweight web server. nginx can be customized by changing its configuration file, which is located in /etc/nginx.


```shell
$ ls -l # List files and directories in long format (including permissions, owner, size, date, etc.)
$ ls -la # List all files and directories, including hidden ones, in long format
$ cat .bashrc # The .bashrc file is used to configure user-specific terminal behavior and customization
$ ls /etc # List the contents of the /etc directory
$ cat /etc/bash.bashrc # Display the contents of the bash.bashrc file
$ nano .bashrc # Launch nano and automatically load the .bashrc file in it
$ nano -l # After typing nano include a space and the -l switch to turn on line-numbering
$ sudo nano -l /etc/nginx/custom_server.conf # Open nginx’s configuration file in a nano
$ sudo nginx -c custom_server.conf  # Execute nginx using the modified configuration file
$ sudo pkill nginx # Shut down the nginx webserver
```

### 2.2.7 Lab - Getting Familiar with the Linux Shell

#### Part 1: Shell Basics
You can display command line help using the `man` command. A man page, short for manual page, is a built-in documentation of the Linux commands. A man page provides detailed information about a given command and all its available options.

```shell
$ man man # Display the manual page for the 'man' command
$ man cp # Display the manual page for the 'cp' command
$ man pwd # Display the manual page for the 'pwd' command
$ pwd # Print name of current/working directory
$ cd /home/cisco # Navigate to the /home/cisco directory
$ ls -l # List the files and folders that are in the current directory
$ mkdir cyops # Create a new directory named cyops
$ cd /home/cisco/cyops # Navigate to the /home/cisco/cyops directory
$ cd ~ # Navigate to the home directory
```
Note: The tilde symbol ~ represents the current user’s home directory in the prompt. $ (dollar sign) indicates regular user privilege. If a ‘#’ (hashtag or pound sign) is displayed at the prompt, it indicates elevated privilege (root user).

```shell
$ ls -la
total 216
drwxr-x--- 11 cisco cisco  4096 Nov  7 22:31 .
drwxr-xr-x  9 root  root   4096 Nov  1 21:12 ..

$ cd . # Stay in the current directory (no actual change in the working directory)
$ cd .. # Change the current directory to the parent directory (one level up)
```
Note: The -a option tells ls to show all files. Notice the . and .. listings shown by ls. These listings are used by the operating system to track the current directory (.) and the parent directory (..).

Note: A forward slash / is used to represent the root directory of the filesystem.

```shell
echo # Display a line of text

$ echo message # Echo a message, because no output was defined, echo will output to the current terminal window
message
```

Another powerful command line operator in Linux is known as redirect. Represented by the > symbol, this operator allows the output of a command to be redirected to some location other the current terminal window (the default).

```shell
$ echo first message > .txt # Redirect the output of echo to a text file instead of to the screen using the > operator
$ cat .txt 
first message

$ echo second message > .txt
$ cat .txt 
second message
```

Note: The > operator destroys the contents of the txt file before writing the message echoed by echo.

Similar to the > operator, the >> operator also allows for redirecting data to files. The difference is that >> appends data to the end of the referred file, keeping the current contents intact.

```shell
$ echo third message >> .txt
$ cat .txt 
second message
third message
```

In Linux, files with names that begin with a ‘.’ (single dot) are not shown by default. While dot-files have nothing else special about them, they are called hidden files because of this feature. Examples of hidden files are .file5, .file6, .file7.

#### Part 2: Copying, Deleting, and Moving Files

```shell
$ ls -l # Display the files stored in the current directory
$ ls -la # Display all files in the current directory, including the hidden files
```
The `cp` command is used to copy files around the local file system. When using cp, a new copy of the file is created and placed in the specified location, leaving the original file intact. The first parameter is the source file and the second is the destination.

```shell
$ cp .txt cyops/ # Copy the file from /home/cisco/.txt to /home/cisco/cyops/.txt
```

Use the `rm` command to remove files. In Linux, directories are seen as a type of file. As such, the rm command is also used to delete directories but the -r (recursive) option must be used. Notice that all files and other directories inside a given directory are also deleted when deleting a parent directory with the -r option.

```shell
$ rm .txt # Remove the .txt file from the current directory
$ rm -r cyops # Remove the cyops directory
```

Moving files works similarly to copying files. The difference is that moving a file removes it from its original location. Use the `mv` commands to move files around the local filesystem. 

```shell
$ mv cyops/.txt .. # Moves the .txt file from the cyops directory to the parent directory
```

## 2.3. Linux Servers and Clients

### 2.3.1 An Introduction to Client-Server Communications
Servers are computers with software installed that enables them to provide services to clients across the network. There are many types of services. Some provide external resources such as files, email messages, or web pages to clients upon request. Other services run maintenance tasks such as log management, memory management, disk scanning, and more. Each service requires separate server software.

### 2.3.2 Servers, Services, and Their Ports
In order that a computer can be the server for multiple services, ports are used. A port is a reserved network resource used by a service. A server is said to be “listening” on a port when it has associated itself to that port.

While the administrator can decide which port to use with any given service, many clients are configured to use a specific port by default. It is common practice to leave the service running in its default port. The table lists a few commonly used ports and their services. These are also called “well-known ports”.

| Port     | Description                                      
|----------|--------------------------------------------------
| 20 / 21    | File Transfer Protocol (FTP)                    
| 20 | File Transfer Protocol - Data (FTP-DATA) 
| 21 | File Transfer Protocol - Control (FTP)   
| 22       | Secure Shell (SSH)                               
| 23       | Telnet remote login service                      
| 25       | Simple Mail Transfer Protocol (SMTP)            
| 53       | Domain Name System (DNS)                        
| 67 / 68    | Dynamic Host Configuration Protocol (DHCP)       
| 67 | Client to server Dynamic Host Configuration Protocol v4 (DHCPv4) 
| 68 | Server to client Dynamic Host Configuration Protocol v4 (DHCPv4) 
| 69       | Trivial File Transfer Protocol (TFTP)           
| 80       | Hypertext Transfer Protocol (HTTP)              
| 110      | Post Office Protocol version 3 (POP3)           
| 123      | Network Time Protocol (NTP)                     
| 143      | Internet Message Access Protocol (IMAP)         
| 161 / 162  | Simple Network Management Protocol (SNMP)       
| 443      | HTTP Secure (HTTPS)                             


### 2.3.3 Clients
Clients are programs or applications designed to communicate with a specific type of server. Also known as client applications, clients use a well-defined protocol to communicate with the server. Web browsers are web clients that are used to communicate with web servers through the Hyper Text Transfer Protocol (HTTP) on port 80. The File Transfer Protocol (FTP) client is software used to communicate with an FTP server.

### 2.3.4 Lab Video - Use a Port Scanner to Detect Open Ports
Network Mapper, or Nmap, is an open-source utility used for network discovery and security auditing. A common task is to scan local machines to determine potential vulnerabilities including open and unmanaged ports. All workstations require open ports and services to communicate and perform tasks like printing, sharing a file, or browsing the web. Administrators also use Nmap for monitoring hosts or managing service upgrade schedules. Nmap determines what hosts are available on a network, what services are running, what operating systems are running, and what packet filters or firewalls are running. You can use Nmap to detect open ports.

All communication that happens over the internet is exchanged using ports. Every IP host can use two types of ports: TCP and UDP. There can be up to 65,535 of each for any given IP address.

Services that connect to the internet (like web browsers, email clients, and file transfer services) use specific ports to receive information. Therefore, each logical connection is assigned a specific number. The port number also identifies which port it must send or receive traffic through when communicating. The Internet Assigned Number Authority (IANA) assigned the official port numbers and divided these ports into three sub-categories: Well-Known Ports (0-1023), Registered Ports (1024 - 49,151) and Dynamic / Private Ports (49,152 - 65,535).

Security of Logical Ports: Every logical port is subject to a threat and poses a vulnerability to a system, but some of the commonly used ports receive a lot of attention from attackers. Over 75% of all cyberattacks involve just a few common ports. Attackers scan systems to identify opened ports on a target system. 

### 2.3.5 Lab - Use a Port Scanner to Detect Open Ports
``` shell
nmap # Network exploration tool and security / port scanner

$ nmap localhost # Run Nmap / run a basic scan against the system
Nmap scan report localhost (127.0.0.1)
Host is up (0.000091s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
23/tcp open  telnet
# The ports 21, 22, and 23 are open.
```
- Port 21 - Used for FTP (File Transfer Protocol), which facilitates file transfers between clients and servers.
- Port 22 - SSH (Secure Shell) is a remote administration protocol used to control and modify a remote server over the internet. SSH authenticates the remote user and uses cryptography to encrypt all communications to and from the remote server.
- Port 23 - Telnet provides a command line interface for communication with a remote server and transmits using clear-text (there is no encryption).
- Port 631 - CUPS allows a computer to act as a print server. A system running CUPS can accept print jobs from clients and send the print jobs to the appropriate printer. CUPS uses IPP (Internet Printing Protocol).

``` shell
$ sudo nmap -sU localhost # Scan the computer’s UDP ports using  administrative privileges with Nmap
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0000050s latency).
Not shown: 999 closed ports
PORT    STATE SERVICE
123/udp open  ntp
# The port 123 is open.
```

- Port 123 - Used for NTP (Network Time Protocol) to synchronize computer clocks across a network.
- Port 67 and 68 provide client-server Dynamic Host Configuration Protocol (DHCP) services. The DHCP is a network management protocol used on Internet Protocol (IP) networks. It dynamically assigns an IP address and other network configuration parameters to host on the network. This information is required for IP hosts to communicate with other hosts on the IP networks.

```shell
$ nmap -sV localhost # Using the –sV switch with the nmap command performs a version detection.
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
23/tcp open  telnet  Linux telnetd
Service Info: Host: Welcome; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```shell
$ nmap –A localhost # Initiate a script scan / Runs a set of scripts built into Nmap to test specific vulnerabilities / Capture the SSH keys for the host system
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 56:68:77:00:41:7f:50:17:5b:73:82:36:47:c4:bc:2d (RSA)
|   256 0e:52:78:ba:08:2a:d0:e5:be:1b:07:a7:98:3a:c8:50 (ECDSA)
|_  256 f7:9e:03:10:96:94:cc:f4:4f:2a:f2:7c:6a:37:c1:6f (ED25519)
23/tcp open  telnet  Linux telnetd
```
Note: The values of the the SSH hostkeys could be used by an attacker to gain unauthorized remote access to the target host. To prevent the cyber attacker from stealing the key information send the keys by phone, text, or email. This is called out-of-band key exchange.


#### Highly Vulnerable Ports

Many ports must be open for a host to function in a normal computing and communication environment. However, these common ports should be monitored regularly to ensure they are not compromised and being used to attack a victim, provide unauthorized remote access, or being used to hijack a host to participate in a distributed attack on other victims.

Port 21 of TCP is one of the most popular ports for attackers. This port is designed to transmit and receive files from one host to another. Attackers use this port to perform the following types of malicious activity:

- Unauthorized transfer, deletion, and modification of files
- Unauthorized transfer of malicious code or payloads
- Anonymous authentication to host file systems
- Inject malicious scripts like XSS attack
- Impact the availability of other host services

An unauthorized user only needs your username and password to gain access to a server with an open SSH port. You may see many attempts to log in to the server with default or common logins to gain access.

Other common targets are ports 22 and 23 (SSH) and (Telnet). These ports are designed to provide authorized remote access to an IP host. Port 23 is essentially unsafe because the data transferred in plaintext. Port 22 is much more secure and is preferred when connecting to a remote host. These ports can be utilized by cybercriminals to perform the following types of malicious activity.
- Gain authorized remote access to a host.
- Plant backdoors and other types of malicious codes.
- View sensitive data and credentials.
- Perform man-in-the-middle attacks.
- Impact the availability of other host services.

Another favorite port for attackers is port 53. This port is used for DNS or looking up domain names when browsing the internet or transferring information. This port is the most common exit route for the attacker after an attack. Because this port is rarely monitored, attackers use this port to exit after clearing their files, logs, and other information to cover their tracks.

The most common port used by attackers is TCP port 80. This port transfers webpages between a web server and the host browser. Attackers use this port to perform the following types of malicious activity:

- Unauthorized transfer, deletion, and modification of data
- Unauthorized transfer of malicious code or payloads
- Injection of malicious scripts (like an XSS attack)
- Impact the availability of other host services

UDP Port 631 is a popular protocol in TCP/IP networks.
The term CUPS (Common UNIX Printing System) is modular network printing service for Linux host which allows a computer to act as a print server. UPS consists of a print spooler and scheduler, a filter system that converts the print data to a format that the printer will understand, and a backend system that sends this data to the print device.
An unauthorized user may be able to execute arbitrary commands with the privileges of the CUPS daemon. Additionally, a remote DoS may cause the server to be unresponsive.

An open port 68 provides Dynamic Host Configuration Protocol (DHCP) services.
This port allows hackers to disrupt dynamic network addressing and can be used for network spoofing and remote code execution.

An open port 631 allows cyber attackers to cause a denial of service and possibly execute arbitrary code.

An open port 5353 is used by Multicast Domain Name System (mDNS) which allows hosts to resolve hostnames to IP addresses in small networks that do not include a name server. However, if the mDNS port 5353 is exposed to the internet, attackers can query the service collect information about the server as well as launch a DoS attack by spoofing a target and flooding the network with mDNS requests.

### 2.3.6 Lab - Linux Servers

#### Part 1: Servers
Servers are essentially programs written to provide specific information upon request. Clients, which are also programs, reach out to the server, place the request, and wait for the server response. Many different client-server communication technologies can be used, with the most common being IP networks.

Many different programs can be running on a given computer, especially a computer running a Linux operating system. Many programs run in the background so users may not immediately detect what programs are running on a given computer. In Linux, running programs are also called processes.

```shell
$ ps # Report a snapshot of the current processes.
    PID TTY          TIME CMD
   1908 pts/0    00:00:00 bash
  46642 pts/0    00:00:00 ps

$ sudo ps -elf # Display all the programs running in the background
```
Note: It's necessary to run `ps` as root since some processes do not belong to the current user, which is a regular user account, and may not be displayed if ps was executed without `sudo`.

```shell
$ sudo /usr/sbin/nginx # Start the nginx webserver with elevated privileges
$ sudo ps –ejH # Display the currently running process tree.
$ sudo ps –ejH | grep nginx # Search for 'nginx' in the ps command output
    PID    PGID     SID TTY          TIME CMD
  46649   46649   46649 ?        00:00:00   nginx
  46650   46649   46649 ?        00:00:00     nginx
  46651   46649   46649 ?        00:00:00     nginx
# The hierarchy is represented through indentation.
```
As mentioned before, servers are essentially programs, often started by the system itself at boot time. The task performed by a server is called a service. In such fashion, a web server provides web services.

The netstat command is a great tool to help identify the network servers running on a computer. The power of netstat lies on its ability to display network connections.

```shell
netstat # Print network connections, routing tables, interface statistics, masquerade connections, and multicast memberships
$ netstat # 
$ netstat -tunap # 
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 127.0.0.1:323           0.0.0.0:*                           -
udp6       0      0 ::1:323                 :::*                                -
# -a: shows both listen and non-listening sockets. -n: use numeric output (no DNS, service port or username resolution), -p: show the PID of the connection owner process. -t: shows TCP connections. –u: shows UDP connections

$ sudo netstat -tunap | grep nginx # Search for 'nginx' in the netstat command output
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      46649/nginx: master 
tcp6       0      0 :::80                   :::*                    LISTEN      46649/nginx: master 
```

Clients will connect to a port and, using the correct protocol, request information from a server. The netstat output above displays a number of services that are currently listening on specific ports. Interesting columns are:
- The first column shows the Layer 4 protocol in use (UDP or TCP, in this case).
- The third column uses the format to display the local IP address and port on which a specific server is reachable. The IP address 0.0.0.0 signifies that the server is currently listening on all IP addresses configured in the computer.
- The fourth column uses the same socket format to display the address and port of the device on the remote end of the connection. 0.0.0.0:* means that no remote device is currently utilizing the connection.
- The fifth column displays the state of the connection.
- The sixth column displays the process ID (PID) of the process responsible for the connection. It also displays a short name associated to the process.

```shell
$ sudo ps -elf | grep 46649 # Filter ps command output for only the lines containing the nginx PID
1 S root       46649       1  0  80   0 - 13804 sigsus 00:40 ?        00:00:00 nginx: master process /usr/sbin/nginx
5 S www-data   46650   46649  0  80   0 - 13963 ep_pol 00:40 ?        00:00:00 nginx: worker process
5 S www-data   46651   46649  0  80   0 - 13963 ep_pol 00:40 ?        00:00:00 nginx: worker process
0 S cisco      46690    1908  0  80   0 -  1619 pipe_r 00:53 pts/0    00:00:00 grep --color=auto 46649
# The first line shows a process owned by the root user, started by another process with PID 1
# The second and third line show a process with PID 46650 and 46651, owned by the www-data user, started by process 46649
# The fourth line shows a process owned by the cisco user, with PID 46690, started by a process with PID 1908, as the grep 46649 command.
```
Note: Netstat allows for an analyst to display all the connections currently present on a computer. Source and destination addresses, ports, and process IDs can also be displayed, providing a quick overview of all connections present on a computer.

#### Part 2: Using Telnet to Test TCP Services
Telnet is a simple remote shell application. Telnet is considered insecure because it does not provide encryption. Administrators who choose to use Telnet to remotely manage network devices and servers will expose login credentials to that server, as Telnet will transmit session data in clear text. While Telnet is not recommended as a remote shell application, it can be very useful for quickly testing or gathering information about TCP services.

The Telnet protocol operates on port 23 using TCP by default. The telnet client however, allows for a different port to be specified. By changing the port and connecting to a server, the telnet client allows for a network analyst to quickly assess the nature of a specific server by communicating directly to it.

Note: It is strongly recommended that ssh be used as remote shell application instead of telnet.

```shell
$ telnet 127.0.0.1 80 # Connect to the local host on port 80 TCP using telnet
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
x
HTTP/1.1 400 Bad Request
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 08 Nov 2023 01:14:40 GMT
Content-Type: text/html
Content-Length: 166
Connection: close
# The nginx with PID 46649 is in fact a web server.
# The version of nginx is 1.18.0.
# The network stack is fully functional all the way to Layer 7.
```

Note: Thanks to the Telnet protocol, a clear text TCP connection was established, by the Telnet client, directly to the nginx server, listening on 127.0.0.1 port 80 TCP. This connection allows us to send data directly to the server. Because nginx is a web server, it does not understand the sequence of random letters sent to it ("x") and returns an error in the format of a web page. Nginx is a web server and as such, only speaks the HTTP protocol.

```shell
$ telnet 127.0.0.1 22 # Connect to the local host on port 22 TCP using telnet
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2
x
Invalid SSH identification string.
Connection closed by foreign host.

$ telnet 127.0.0.1 68
Trying 127.0.0.1...
telnet: Unable to connect to remote host: Connection refused
# Unable to connect because the connection is refused. Telnet is a TCP-based protocol and will not be able to connect to UDP ports.
```

Note: As long as Telnet is not used as a remote shell. It is perfectly safe to quickly test or gather information about a given network service.

## 2.4. Basic Server Administration

### 2.4.1 Service Configuration Files
In Linux, services are managed using configuration files. Common options in configuration files are port number, location of the hosted resources, and client authorization details. When the service starts, it looks for its configuration files, loads them into memory, and adjusts itself according to the settings in the files. Configuration file modifications often require restarting the service before the changes take effect.

Note: Because services often require superuser privileges to run, service configuration files often require superuser privileges to edit.

```shell
$ cat /etc/nginx/nginx.conf # Shows the configuration file for Nginx, which is a lightweight web server for Linux
$ cat /etc/ntp.conf # Shows the configuration file for the network time protocol (NTP)
$ cat /etc/snort/snort.conf # Shows the configuration file for Snort, a Linux-based intrusion detection system (IDS).
```
Note: There is no rule for a configuration file format; it is the choice of the service’s developer. However, the option = value format is often used. 

### 2.4.2 Hardening Devices
Device hardening involves implementing proven methods of securing the device and protecting its administrative access. Some of these methods involve maintaining passwords, configuring enhanced remote login features, and implementing secure login with SSH. Defining administrative roles in terms of access is another important aspect of securing infrastructure devices because not all information technology personnel should have the same level of access to the infrastructure devices.

Depending on the Linux distribution, many services are enabled by default. Some of these features are enabled for historical reasons but are no longer required. Stopping such services and ensuring they do not automatically start at boot time is another device hardening technique.

OS updates are also extremely important to maintaining a hardened device. New vulnerabilities are discovered every day. OS developers create and issue fixes and patches regularly. An up-to-date computer is less likely to be compromised.

The following are basic best practices for device hardening.
- Ensure physical security
- Minimize installed packages
- Disable unused services
- Use SSH and disable the root account login over SSH
- Keep the system updated
- Disable USB auto-detection
- Enforce strong passwords
- Force periodic password changes
- Keep users from re-using old passwords


### 2.4.3 Monitoring Service Logs
Log files are the records that a computer stores to keep track of important events. Kernel, services, and application events are all recorded in log files. It is very important for an administrator to periodically review the logs of a computer to keep it healthy. By monitoring Linux log files, an administrator gains a clear picture of the computer’s performance, security status, and any underlying issues. Log file analysis allows an administrator to guard against upcoming issues before they occur.

In Linux, log files can be categorized as:

- Application logs
- Event logs
- Service logs
- System logs

Some logs contain information about daemons that are running in the Linux system. A daemon is a background process that runs without the need for user interaction. For example, the System Security Services Daemon (SSSD) manages remote access and authentication for single sign-on capabilities.

The table lists a few popular Linux log files and their functions.
| Linux Log File              | Description                                                                                                 |
|-----------------------------|-------------------------------------------------------------------------------------------------------------|
| /var/log/messages           | This directory contains generic computer activity logs. It is mainly used to store informational and non-critical system messages. In Debian-based computers, /var/log/syslog directory serves the same purpose.                               |
| /var/log/auth.log           | This file stores all authentication-related events in Debian and Ubuntu computers. Anything involving the user authorization mechanism can be found in this file.                             |
| /var/log/secure             | This directory is used by RedHat and CentOS computers instead of /var/log/auth.log. It also tracks sudo logins, SSH logins, and other errors logged by SSSD.                                   |
| /var/log/boot.log           | This file stores boot-related information and messages logged during the computer startup process.         |
| /var/log/dmesg              | This directory contains kernel ring buffer messages. Information related to hardware devices and their drivers is recorded here. It is very important because, due to their low-level nature, logging systems such as syslog are not running when these events take place and therefore are often unavailable to the administrator in real-time. |
| /var/log/kern.log           | This file contains information logged by the kernel.                                                        |
| /var/log/cron               | Cron is a service used to schedule automated tasks in Linux and this directory stores its events.  Whenever a scheduled task (also called a cron job) runs, all its relevant information including execution status and error messages are stored here. |
| /var/log/mysqld.log or /var/log/mysql.log | This is the MySQL log file. All debug, failure, and success messages related to the mysqld process and mysqld_safe daemon are logged here. RedHat, CentOS, and Fedora Linux distributions store MySQL logs under /var/log/mysqld.log, while Debian and Ubuntu maintain the log in /var/log/mysql.log file. |



```shell
$ sudo cat /var/log/messages # Shows the /var/log/messages log file
# Each line represents a logged event. The timestamps at the beginning of the lines mark the moment the event took place.
```

### 2.4.4 Lab - Locating Log Files

#### Part 1: Log File Overview
Log files (also spelled logfiles), are files used by computers to log events. Software programs, background processes, services, or transactions between services, including the operating system itself, may generate such events. Log files are dependent on the application that generates them. It is up to the application developer to conform to log file convention. Software documentation should include information on its log files.

Because log files are essentially a way to track specific events, the type of information stored varies depending of the application or services generating the events.

```shell
# Web server log file example
[Wed Mar 22 11:23:12.207022 2017] [core:error] [pid 3548:tid 4682351596] [client 209.165.200.230] File does not exist: /var/www/apache/htdocs/favicon.ico
```

The single log entry above represents a web event recorded by Apache, a popular web server. A few pieces of information are important in web transactions, including client IP address, time and details of the transaction. The entry above can be broken down into five main parts:
1. Timestamp: This part records when the event took place. It is very important that the server clock is correctly synchronized as it allows for accurately cross-referencing and tracing back events.
2. Type: This is the type of event. In this case, it was an error.
3. PID: This contains information about the process ID used by Apache at the moment.
4. Client: This records the IP address of the requesting client.
5. Description: This contains a description of the event.

> On Wednesday, March 22nd, 11:23:12.207022 am of 2017, a client with IP address of 209.165.200.230 requested a non-existent file named favicon.ico. The file should have been located in the following path /var/www/apache/htdocs/favicon.ico, but because it could not be found, it triggered an error.

```shell
$ cat /var/log/logstash-tutorial.log # Displays the /var/log/logstash-tutorial.log file, which includes web events.
```
Any software can keep log files, including the operating system itself. Conventionally, Linux uses the /var/log directory to stores various log files, including operating system logs. Modern operating systems are complex pieces of software and therefore use several different files to log events.

```shell
$ sudo more /var/log/messages # Displays the events logged to the /var/more/messages file, which are in relation to the operating system itself.
```
#### Part 2: Locating Log Files in Unknown Systems
When working with new software, the first step is to look at the documentation. It provides important information about the software, including information about its log files.

```shell
$ man nginx # Display the nginx manual page
# Because the location to the log files was not specified in the manual, the global nginx configuration file should be checked for the location of the log files.

$ ps ax | grep nginx # Ensure nginx is running in the VM
  46649 ?        Ss     0:00 nginx: master process /usr/sbin/nginx
  46650 ?        S      0:00 nginx: worker process
  46651 ?        S      0:00 nginx: worker process
  46745 pts/0    S+     0:00 grep --color=auto nginx

$ $ ls /etc/ # Search for the nginx configuration directory
$ ls -l /etc/nginx/ # Search for the nginx configuration file
$ cat /etc/nginx/nginx.conf # Check the nginx configuration file
# There is no direct mention to the location of nginx log files, it is very likely that nginx is using default values for it. Following the convention of storing log files under /var/log

$ ls -l /var/log/ # Search for the nginx log directory
$ sudo ls -l /var/log/nginx # Search for the nginx log file
```

#### Part 3: Monitoring Log Files in Real Time
Log files can be displayed with many text-presentation tools. While cat, more, less, and nano can be used to work with log files, they are not suitable for log file real-time monitoring. Developers designed various tools that allow for log file real-time monitoring. Some tools are text-based while others have a graphical interface. 

Tail is a simple but efficient tool, available in practically every Unix-based system.

```shell
tail # output the last part of files
$ sudo tail /var/log/nginx/access.log # Display the end of /var/log/nginx/access.log
$ sudo tail -n 5  /var/log/nginx/access.log # Display the last five lines of /var/log/nginx/access.log
$ sudo tail -f / var/log/nginx/access.log # Monitor the nginx access.log in real-time / Continuously display the end of a text file
```

Arch Linux uses systemd as its init system. In Linux, the init process is the first process loaded when the computer boots. Init is directly or indirectly, the parent of all processes running on the system. It is started by the kernel at boot time and continues to run until the computer shuts down. Typically, init has the process ID 1.

An init system is a set of rules and conventions governing the way the user space in a given Linux system is created and made available to the user. Init systems also specify system-wide parameters such as global configuration files, logging structure and service management.

Systemd is a modern init system designed to unify Linux configuration and service behavior across all Linux distributions and has been increasingly adopted by major Linux distributions. Arch Linux relies on systemd for init functionality.

system-journald (or simply journald) is systemd’s event logging service and uses append-only binary files serving as its log files. Notice that journald does not impede the use of other logging systems, such as syslog and rsyslog.

```shell
journalctl # Query the systemd journal
$ sudo journalctl # Display all journal log entries
$ sudo journalctl -b # Display boot-related log entries
$ sudo journalctl -1 # Display the entries related to the last boot
$ sudo journalctl -2 # Display the entries related to the two last boots
$ sudo journalctl –-list-boots # List previous boots
$ sudo journalctl –-since '2 hours ago' # Display all log entries generated in the last two hours
$ sudo journalctl –-since '1 day ago' # Display all log entries generated in the last day
$ sudo journalctl –u nginx.service # Display logs entries related to nginx
$ sudo journalctl -f # Real-time monitoring / Instruct journalctl to follow a specific log with the -f option
$ sudo journalctl -u nginx.service -f # Monitors nginx system events in real time
```

Log files are extremely important for troubleshooting. Log file location follows convention but ultimately, it is a choice of the developer. More often than not, log file information (location, file names, etc.) is included in the documentation. If the documentation does not provide useful information on log files, a combination of web research, and system investigation should be used.

Clocks should always be synchronized to ensure all systems have the correct time. If clocks are not correctly set, it is very difficult to trace back events. It is important to understand when specific events took place. In addition to that, events from different sources are often analyzed at the same time.

## 2.5. The Linux File System

### 2.5.1 The File System Types in Linux
There are many different kinds of file systems, varying in properties of speed, flexibility, security, size, structure, logic and more. It is up to the administrator to decide which file system type best suits the operating system and the files it will store.

- ext2 (second extended file system)
   - ext2 was the default file system in several major Linux distributions until supplanted by ext3.
   - Almost fully compatible with ext2, ext3 also supports journaling.
   - ext2 is still the file system of choice for flash-based storage media because its lack of a journal increases performance and minimizes the number of writes.
   - Because flash memory devices have a limited number of write operations, minimizing write operations increases the device’s lifetime.
   - However, contemporary Linux kernels also support ext4, an even more modern file system, with better performance and which can also operate in a journal-less mode.

- ext3 (third extended file system)
   - ext3 is a journaled file system designed to improve the existing ext2 file system.
   - A journal, the main feature added to ext3, is a technique used to minimize the risk of file system corruption in the event of sudden power loss.
   - The file systems keep a log (or journal) of all the file system changes about to be made.
   - If the computer crashes before the change is complete, the journal can be used to restore or correct any eventual issues created by the crash.
   - The maximum file size in ext3 file systems is 32 TB.

- ext4 (fourth extended file system)
   - Designed as a successor of ext3, ext4 was created based on a series of extensions to ext3.
   - While the extensions improve the performance of ext3 and increase supported file sizes, Linux kernel developers were concerned about stability issues and were opposed to adding the extensions to the stable ext3.
   - The ext3 project was split in two; one kept as ext3 and its normal development and the other, named ext4, incorporated the mentioned extensions.

- NFS (Network File System)
   - NFS is a network-based file system, allowing file access over the network.
   - From the user standpoint, there is no difference between accessing a file stored locally or on another computer on the network.
   - NFS is an open standard which allows anyone to implement it.

- CDFS (Compact Disc File System)
   - CDFS was created specifically for optical disk media.

- Swap File System
   - The swap file system is used by Linux when it runs out of RAM.
   - Technically, it is a swap partition that does not have a specific file system, but it is relevant to the file system discussion.
   - When this happens, the kernel moves inactive RAM content to the swap partition on the disk.
   - While swap partitions (also known as swap space) can be useful to Linux computers with a limited amount of memory, they should not be considered as a primary solution.
   - Swap partition is stored on disk which has much lower access speeds than RAM.

- HFS Plus or HFS+ (Hierarchical File System Plus)
   - A file system used by Apple in its Macintosh computers.
   - The Linux kernel includes a module for mounting HFS+ for read-write operations.

- APFS (Apple File System)
   - An updated file system that is used by Apple devices. It provides strong encryption and is optimized for flash and solid-state drives.

- Master Boot Record (MBR)
   - Located in the first sector of a partitioned computer, the MBR stores all the information about the way in which the file system is organized.
   - The MBR quickly hands over control to a loading function, which loads the OS.

Mounting is the term used for the process of assigning a directory to a partition. After a successful mount operation, the file system contained on the partition is accessible through the specified directory. In this context, the directory is called the mounting point for that file system.

Note: The root file system is represented by the “/” symbol and holds all files in the computer by default.

```shell
$ mount # Returns the list of file systems currently mounted in a Linux computer
/dev/sda2 on / type ext4 (rw,relatime)
# The root file system was formatted as ext4 and occupies the first partition of the first drive (/dev/sda1).
```

### 2.5.2 Linux Roles and File Permissions
In Linux, most system entities are treated as files. In order to organize the system and enforce boundaries within the computer, Linux uses file permissions. File permissions are built into the file system structure and provide a mechanism to define permissions on every file. Every file in Linux carries its file permissions, which define the actions that the owner, the group, and others can perform with the file. The possible permission rights are Read, Write and Execute. The ls command with the -l parameter lists additional information about the file.

```shell
$ ls -l .txt
-rwxrw-r-- 1 root cisco 253 May 20 12:49 .txt
```

- The first field of the output displays the permissions that are associated with .txt (-rwxrw-r--).
    - The dash (-) means that this is a file. For directories, the first dash would be a “d”.
    - The first set of characters is for user permission (rwx ). The user, root, who owns the file can Read, Write and eXecute the file.
    - The second set of characters is for group permissions (rw-). The group, cisco, who owns the file can Read and Write to the file.
    - The third set of characters is for any other user or group permissions (r--). Any other user or group on the computer can only Read the file.
- The second field defines the number of hard links to the file. A hard link creates another file with a different name linked to the same place in the file system (called an inode).
- The third and fourth field display the user (root) and group (cisco) who own the file, respectively.
- The fifth field displays the file size in bytes. The .txt file has 253 bytes.
- The sixth field displays the date and time of the last modification.
- The seventh field displays the file name.

| Binary | Octal | Permission | Description         |
|--------|-------|------------|---------------------|
| 000    | 0     | ---        | No access           |
| 001    | 1     | --x        | Execute only        |
| 010    | 2     | -w-        | Write only          |
| 011    | 3     | -wx        | Write and Execute   |
| 100    | 4     | r--        | Read only           |
| 101    | 5     | r-x        | Read and Execute    |
| 110    | 6     | rw-        | Read and Write      |
| 111    | 7     | rwx        | Read, Write and Execute |

File permissions are a fundamental part of Linux and cannot be broken. A user has only the rights to a file that the file permissions allow. The only user that can override file permission on a Linux computer is the root user. Because the root user has the power to override file permissions, the root user can write to any file. Because everything is treated as a file, the root user has full control over a Linux computer. Root access is often required before performing maintenance and administrative tasks. Because of the power of the root user, root credentials should use strong passwords and not be shared with anyone other than system administrators and other high-level users.

### 2.5.3 Hard Links and Symbolic Links
A hard link is another file that points to the same location as the original file. Use the command ln to create a hard link. The first argument is the existing file and the second argument is the new file. As shown in the command output, the file .txt is linked to hard.txt and the link field now shows 2.

```shell
ln # Make links between files / Create a hard link
$ ln .txt hard.txt # Create a hard link between the .txt and hard.txt files

$ ls -l .txt*
-rw-r--r-- 2 analyst analyst 239 May 7 18:18 hard.txt
-rw-r--r-- 2 analyst analyst 239 May 7 18:18 .txt

$ echo "Testing hard link" >> hard.txt # Append a phrase to hard.txt

$ ls -l .txt*
-rw-r--r-- 2 analyst analyst 257 May 7 18:19 hard.txt
-rw-r--r-- 2 analyst analyst 257 May 7 18:19 .txt

$ rm hard.txt # Remove hard.txt

$ more .txt # Show .txt
...
Testing hard link

# Both files point to the same location in the file system. If you change one file, the other is changed, as well. The echo command is used to add some text to .txt. Notice that the file size for both .txt and hard.txt increased to 257 bytes. If you delete the hard.txt with the rm command (remove), the .txt file still exists, as verified with the more .txt command.
```

A symbolic link, also called a symlink or soft link, is similar to a hard link in that applying changes to the symbolic link will also change the original file. As shown in the command output below, use the ln command option -s to create a symbolic link.

```shell
$ echo "Hello World!" > .txt # Write a phrase to the .txt file

$ ln -s .txt symbolic.txt # Create a symbolic link between the .txt and symbolic.txt files

$ echo "It's a lovely day!" >> test .txt # Append a phrase to symbolic.txt

$ more .txt # Show .txt
Hello World!
Its a lovely day!

$ rm .txt # Remove .txt

$ more symbolic.txt # Show symbolic.txt
more: stat of symbolic.txt failed: No such file or directory

$ ls -l symbolic.txt
lrwxrwxrwx 1 analyst analyst 8 May 7 20:17 symbolic.txt -> .txt

# Notice that adding a line of text to .txt also adds the line to symbolic.txt. However, unlike a hard link, deleting the original .txt file means that symbolic.txt is now linked to a file that no longer exists, as shown with the 'more symbolic.txt' and 'ls -l symbolic.txt' commands.
```

Although symbolic links have a single point of failure (the underlying file), symbolic links have several benefits over hard links:
- Locating hard links is more difficult. Symbolic links show the location of the original file in the ls -l command, as shown in the last line of output in the previous command output (symbolic.txt -> .txt).
- Hard links are limited to the file system in which they are created. Symbolic links can link to a file in another file system.
- Hard links cannot link to a directory because the system itself uses hard links to define the hierarchy of the directory structure. However, symbolic links can link to directories.

### 2.5.4 Lab - Navigating the Linux Filesystem and Permission Settings

#### Part 1: Exploring Filesystems in Linux
Filesystems must be mounted before they can be accessed and used. In computing, mounting a filesystem means to make it accessible to the operating system. Mounting a filesystem is the process of linking the physical partition on the block device (hard drive, SSD drive, pen drive, etc.) to a directory, through which the entire filesystem can be accessed. Because the aforementioned directory becomes the root of the newly mounted filesystem, it is also known as mounting point.

```shell
$ lsblk # Diplay all block devices
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda      8:0    0 23.4G  0 disk 
├─sda1   8:1    0    1M  0 part 
└─sda2   8:2    0 23.4G  0 part /
sdb      8:16   0    1G  0 disk 
└─sdb1   8:17   0 1023M  0 part
# There are two block devices installed: sda and sdb. The tree-like output shows partitions under sda and sdb. 
```

Conventionally, /dev/sdX is used by Linux to represent hard drives, with the trailing number representing the partition number inside that device. Computers with multiple hard drives would likely display more /dev/sdX devices. If Linux was running on a computer with four hard drives for example, it would show them as /dev/sda, /dev/sdb, /dev/sdc and /dev/sdd, by default. The output implies that sda and sdb are hard drives, each one containing a single partition. The output also shows that sda is a 23.4GB disk while sdb has 1GB.

```shell
$ mount # Display detailed information on the currently mounted filesystems
/dev/sda1 on / type ext4 (rw,relatime)
# The root filesystem is stored in /dev/sda1
```
The root filesystem is where the Linux operating system itself is stored; all the programs, tools, configuration files are stored in root filesystem by default.

The mount command can also be used to mount and unmount filesystems.

```shell
$ mkdir second_drive # Create the second_drive directory
$ sudo mount /dev/sdb1 ~/second_drive/ # Mount the /dev/sdb1 filesystem on the second_drive directory
$ ls -l second_drive/ # Check the second_drive directory
total 20
drwx------ 2 root    root     16384 Mar  3 10:59 lost+found
-rw-r--r-- 1 root    root       183 Mar  3 15:42 myFile.txt

$ mount | grep /dev/sd # Display detailed information about /dev/sdX filesystems
/dev/sda1 on / type ext4 (rw,relatime)
/dev/sdb1 on /home/cisco/second_drive type ext4 (rw,relatime)

$ sudo umount /dev/sdb1 # Unmount /dev/sdb1 filesystem
$ ls -l second_drive/
total 0
```

#### Part 2: File Permissions
Linux filesystems have built-in features to control the ability of the users to view, change, navigate, and execute the contents of the filesystem. Essentially, each file in filesystems carries its own set of permissions, always carrying a set of definitions about what users and groups can do with the file.

```shell
$ cd lab.support.files/scripts/ # Navigate to the lab.support.files/scripts/ directory
$ ls -l # Display file permissions
total 60
-rw-r--r-- 1 root cisco 2871 Apr 28 11:27 cyops.mn
# Owner: root; Group: cisco
# Permissions - Owner: Read and Write; Group: Read; Other: Read

$ ls -ld /mnt
drwxr-xr-x 2 root root 4096 Jan  5  2018 /mnt
# Only the root user is allowed to write to the /mnt folder.
$ sudo touch /mnt/.txt # Create an empty text file in the mnt/ directory

$ sudo chmod 665 /mnt/.txt # Change the permissions of a file
# The file permissions are now -rw-rw-r-x
```

The chmod command is used to change the permissions of a file or directory. The chmod command takes permissions in the octal format, a breakdown of the 665 is as follows: 6 in octal is 110 in binary. Each position of the permissions of a file can be 1 or 0, 110 means rw- (read=1, write=1 and execute=0).

The chmod 665 .txt command changes the permissions to:
- Owner: rw- (6 in octal or 110 in binary)
- Group: rw- (6 in octal or 110 in binary)
- Other: r-x (5 in octal or 101 in binary)

The command 'sudo chmod 777 .txt' would change the permissions of .txt to rwxrwxrwx, granting any user in the system full access to the file.

```shell
$ sudo chown root .txt # Make root the owner of the .txt file
$ sudo chown root:cisco .txt # Make root the owner and cisco the group of the .txt file
```
The chown command is used to change ownership of a file or directory. 

```shell
$ cd ~/lab.support.files/
total 580
drwxr-xr-x 4 analyst analyst   4096 Aug  7 15:29 attack_scripts
drwxr-xr-x 2 analyst analyst   4096 May 25 13:01 malware
```
The letter ‘d’ at the beginning of the line indicates that the file type is a directory and not a file. Another difference between file and directory permissions is the execution bit. If a file has its execution bit turned on, it means it can be executed by the system. Directories are different than files with the execution bit set (a file with the execution bit set is an whether a user can enter that directory.

#### Part 3: Symbolic Links and other Special File Types
The three different types of files in Linux including their sub-types and characters are:

- Regular files (-)
    - Readable files – text files
    - Binary files - programs
    - Image files
    - Compressed files
- Directory files (d)
    - Folders
- Special Files
    - Block files (b) – Files used to access physical hardware like mount points to access hard drives.
    - Character device files (c) – Files that provide a serial stream of input and output. tty terminals are examples of this type of file.
    - Pipe files (p) – A file used to pass information where the first bytes in are the first bytes out. This is also known as FIFO (first in first out).
    - Symbolic Link files (l) – Files used to link to other files or directories. There are two types: symbolic links and hard links.
    - Socket files (s) – These are used to pass information from application to application in order to communicate over a network.

Note: When using the ls -l command to display the files in a directory, notice the first characters of each line are either a “–“ indicating a file or a “d” indicating a directory. The block files begin with a “b”, the character device files begin with a “c” and the symbolic link files begin with an “l”:

```shell
$ echo "symbolic" > file1.txt # Write a word to the file1.txt file
$ echo "hard" > file2.txt # Write a word to the file2.txt file

$ ln –s file1.txt file1symbolic # Create a symbolic link between the file1.txt and file1symbolic files
$ ln file2.txt file2hard # Create a hard link between the file2.txt and file2hard files

$ ls -l
total 40
lrwxrwxrwx 1 analyst analyst    9 Aug 17 16:43 file1symbolic -> file1.txt
-rw-r--r-- 1 analyst analyst    9 Aug 17 16:41 file1.txt
-rw-r--r-- 2 analyst analyst    5 Aug 17 16:42 file2hard
-rw-r--r-- 2 analyst analyst    5 Aug 17 16:42 file2.txt
```

Notice how the file file1symbolic is a symbolic link with an l at the beginning of the line and a pointer -> to file1.txt. The file2hard appears to be a regular file, because in fact it is a regular file that happens to point to the same inode on the hard disk drive as file2.txt. In other words, file2hard points to the same attributes and disk block location as file2.txt. The number 2 in the fifth column of the listing for file2hard and file2.txt indicates that there are 2 files hard linked to the same inode.

Note: For a directory listing the fifth column indicates the number of directories within the directory including hidden folders.

```shell
$ mv file1.txt file1new.txt # Renames file1.txt to file1new.txt
$ mv file2.txt file2new.txt # Renames file2.txt to file2new.txt

$ cat file1symbolic # Check for the file1symbolic file
cat: file1symbolic: no such file or directory

$ cat file2hard # Display file2hard
hard
```
Notice how file1symbolic is now a broken symbolic link because the name of the file that it pointed to file1.txt has changed, but the hard link file file2hard still works correctly because it points to the inode of file2.txt and not its name, which is now file2new.txt.

File permissions and ownership are two of the most important aspects of Linux. They are also a common cause of problems. A file that has the wrong permissions or ownership set will not be available to the programs that need to access it. In this scenario, the program will usually break and errors will be encountered.

## 2.6. Working with the Linux GUI

### 2.6.1 X Window System
The graphical interface present in most Linux computers is based on the X Window System. Also known as X or X11, X Window is a windowing system designed to provide the basic framework for a GUI. X includes functions for drawing and moving windows on the display device and interacting with a mouse and keyboard.

X works as a server which allows a remote user to use the network to connect, start a graphical application, and have the graphical window open on the remote terminal. While the application itself runs on the server, the graphical aspect of it is sent by X over the network and displayed on the remote computer.

Notice that X does not specify the user interface, leaving it to other programs, such as window managers, to define all the graphical components. This abstraction allows for great flexibility and customization as graphical components such as buttons, fonts, icons, window borders, and color schemes are all defined by the user application. Because of this separation, the Linux GUI varies greatly from distribution to distribution. Examples of window managers are Gnome and KDE. While the look and feel of window managers vary, the main components are still present.

### 2.6.2 The Linux GUI
Although an operating system does not require a GUI to function, GUIs are considered more user-friendly than the CLI. The Linux GUI as a whole can be easily replaced by the user. As a result of the large number of Linux distributions, this module focuses on Ubuntu when covering Linux because it is a very popular and user-friendly distribution.

Ubuntu Linux uses Gnome 3 as its default GUI. The goal of Gnome 3 is to make Ubuntu even more user-friendly. Some of the main UI components of Unity are: Apps Menu, Ubuntu Dock, Top Bar, Calendar and System Message Tray, the Activites area, and the Status Menu.

## 2.7. Working on a Linux Host

### 2.7.1 Installing and Running Applications on a Linux Host
Many end-user applications are complex programs written in compiled languages. To aid in the installation process, Linux often includes programs called package managers. A package is the term used to refer to a program and all its supporting files. By using a package manager to install a package, all the necessary files are placed in the correct file system location.

Package managers vary depending on Linux distributions. For example, pacman is used by Arch Linux while dpkg (Debian package) and apt (Advanced Packaging Tool) are used in Debian and Ubuntu Linux distributions.

The apt-get update command is used to get the package list from the package repository and update the local package database. The apt-get upgrade command is used to update all currently installed packages to their latest versions.

### 2.7.2 Keeping the System Up to Date
Also known as patches, OS updates are released periodically by OS companies to address any known vulnerabilities in their operating systems. While companies have update schedules, the release of unscheduled OS updates can happen when a major vulnerability is found in the OS code. Modern operating systems will alert the user when updates are available for download and installation, but the user can check for updates at any time.

The following table compares Arch Linux and Debian / Ubuntu Linux distribution commands to perform package system basic operations.

| Task                               | Arch       | Debian / Ubuntu |
|-----------------------------------|------------|-----------------|
| Install a package by name         | pacman -S  | apt install     |
| Remove a package by name          | pacman -Rs | apt remove      |
| Update a local package            | pacman -Syy | apt-get update  |
| Upgrade all currently installed packages | pacman -Syu | apt-get upgrade |

A Linux GUI can also be used to manually check and install updates. In Ubuntu for example, to install updates you would click Dash Search Box , type software updater , and then click the Software Updater icon.

### 2.7.3 Processes and Forks
A process is a running instance of a computer program. Multitasking operating systems can execute many processes at the same time.

Forking is a method that the kernel uses to allow a process to create a copy of itself. Processes need a way to create new processes in multitasking operating systems. The fork operation is the only way of doing so in Linux.

Forking is important for many reasons. One of them relates to process scalability. Apache, a popular web server, is a good example. By forking itself, Apache is able to serve a large number of requests with fewer system resources than a single-process-based server.

When a process calls a fork, the caller process becomes the parent process, with the newly created process referred to as its child. After the fork, the processes are, to some extent, independent processes; they have different process IDs but run the same program code.

The table lists three commands that are used to manage processes.
| Command | Description |
|---------|-------------|
| ps | Used to list the processes running on the computer at the time it is invoked. It can be instructed to display running processes that belong to the current user or other users. While listing processes does not require root privileges, killing or modifying other user’s processes does. |
| top | Used to list running processes, but unlike ps, top keeps displaying running processes dynamically. Press q to exit top. |
| kill | - Used to modify the behavior of a specific process Depending on the parameters, kill will remove, restart, or pause a process. In many cases, the user will run ps or top before running kill. This is done so the user can learn the PID of a process before running kill. |

### 2.7.4 Malware on a Linux Host
Linux malware includes viruses, Trojan horses, worms, and other types of malware that can affect the operating system. Due to a number of design components such as file system structure, file permissions, and user account restrictions, Linux operating systems are generally regarded as better protected against malware.

While arguably better protected, Linux is not immune to malware. Many vulnerabilities have been found and exploited in Linux. These range from server software to kernel vulnerabilities. Attackers are able to exploit these vulnerabilities and compromise the target. Because Linux is open source, fixes and patches are often made available within hours of the discovery of such problems.

If a malicious program is executed, it will cause damage, regardless of the platform. A common Linux attack vector is its services and processes. Vulnerabilities are frequently found in server and process code running on computers connected to the network. An outdated version of the Apache web server could contain an unpatched vulnerability which can be exploited by an attacker, for example. Attackers often probe open ports to assess the version and nature of the server running on that port. With that knowledge, attackers can research if there are any known issues with that particular version of that particular server to support the attack. As with most vulnerabilities, keeping the computer updated and closing any unused services and ports is a good way to reduce the opportunities for attack in a Linux computer.

```shell
$ telnet 209.165.200.224 80 # An attacker using the Telnet command to probe the nature and version of a web server (port 80).
Trying 209.165.200.224...
Connected to 209.165.200.224.
Escape character is ‘^]’.
HTTP/1.1 400 Bad Request
Server: nginx/1.12.0
Connection closed by foreign host.
# The attacker has learned that the server in question is running nginx version 1.12.0. The next step would be to research known vulnerabilities in the nginx 1.12.0 code.
```

### 2.7.5 Rootkit Check
A rootkit is a type of malware that is designed to increase an unauthorized user’s privileges or grant access to portions of the software that should not normally be allowed. Rootkits are also often used to secure a backdoor to a compromised computer.

The installation of a rootkit can be automated (done as part of an infection) or an attacker can manually install it after compromising a computer. A rootkit is destructive because it changes kernel code and its modules, changing the most fundamental operations of the OS itself. With such a deep level of compromise, rootkits can hide the intrusion, remove any installation tracks, and even tamper with troubleshooting and diagnostic tools so that their output now hides the presence of the rootkit. While a few Linux vulnerabilities through history have allowed rootkit installation via regular user accounts, the vast majority of rootkit compromises require root or administrator access.

Because the very nature of the computer is compromised, rootkit detection can be very difficult. Typical detection methods often include booting the computer from trusted media such as a diagnostics operating system live CD. The compromised drive is mounted and, from the trusted system toolset, trusted diagnostic tools can be launched to inspect the compromised file system. Inspection methods include behavioral-based methods, signature scanning, difference scanning, and memory dump analysis.

Rootkit removal can be complicated and often impossible, especially in cases where the rootkit resides in the kernel; re-installation of the operating system is usually the only real solution to the problem. Firmware rootkits usually require hardware replacement.

chkrootkit is a popular Linux-based program designed to check the computer for known rootkits. It is a shell script that uses common Linux tools such as strings and grep to compare the signatures of core programs. It also looks for discrepancies as it traverses the /proc file system comparing the signatures found there with the output of ps.

```shell
$ sudo ./chkrootkit # Scan the system for signs of rootkits
# While helpful, keep in mind that programs to check for rootkits are not 100% reliable.
```

### 2.7.6 Piping Commands
Although command line tools are usually designed to perform a specific, well-defined task, many commands can be combined to perform more complex tasks by a technique known as piping. Named after its defining character, the pipe (|), piping consists of chaining commands together, feeding the output of one command into the input of another.

For example, the ls command is used to display all the files and directories of a given directory. The grep command compares searches through a file or text looking for the specified string. If found, grep displays the entire contents of the folder where the string was found.

The two commands, ls and grep, can be piped together to filter out the output of ls.

```shell
$ ls -l | grep keyword # Filter the output of the ls -l command
```

### 2.7.7 Video - Applications, Rootkits, and Piping Commands
Installing and updating applications, checking for a rootkit, and using piping commands.

### 2.7.8 Lab - Configure Security Features in Windows and Linux

#### Part 1: Update Windows and Linux / Linux update and upgrade
New flaws and vulnerabilities are discovered all the time. It is a good idea to keep your PC up to date to mitigate the exploitation of the known vulnerabilities.

```shell
$ sudo apt-get update # Resynchronize the package index files from their sources
$ sudo apt-get upgrade # Retrieve and upgrade the currently installed packages with new versions available. 
```
#### Part 2: Windows Local Security Policy
The Windows Local Security Policy of a system is a set of information about the security of your computer.

#### Part 3: Configure Firewall Rules
Traffic travels in and out of devices using ports. The firewall controls the flow of the traffic. Think of the firewall as a security guard who controls the inbound and outbound traffic based on the firewall rules.

#### Part 4: Install and Run Applications
The tool chkrootkit is used to check for signs of a rootkit on a local system. Rootkit is a type of malware that can remain hidden on your computer and can be used to cause significant damage to your device by hackers.
```shell
$ sudo apt install chkrootkit # Install and run chkrootkit
$ sudo chkrootkit # Run chkrootkit
```

lynis is security tool for systems running Unix-based OS, such as Linux and macOS. lynis can be used to harden a Linux system. The application Lynis is maintained by CISOfy. 

```shell
$ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 013baa07180c50a7101097ef9de922f1c2fde6c4 # Import the key from the CISOfy keyserver, which is required to verify the integrity of the download when lynis is downloaded

$ echo 'deb https://packages.cisofy.com/community/lynis/deb/ stable main' | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list # Add the lynis repository maintained by CISOfy

$ sudo apt install lynis # Install lynis

$ lynis show version # Verify the installed version
3.0.7
$ sudo apt-cache policy lynis # Determine the latest version provided by CISOfy
lynis:
  Installed: 3.0.7-1
  Candidate: 3.0.7-1
  Version table:
 *** 3.0.7-1 500
```

Note: 'sudo apt-get update' and 'sudo apt-get upgrade' can be run again to ensure that lynis have all the latest updates from CISOfy.

## 2.8. Linux Overview Summary

### 2.8.1 What Did I Learn in this Module?

#### Linux Basics
Linux is a fast, reliable, and small open-source operating system. It requires few hardware resources to run and is highly customizable. It is designed to be used on networks. The Linux kernel is distributed by different organizations with different tools and software packages. A customized version of Linux that is called Security Onion contains software and tools that are designed for use in network security monitoring by cybersecurity analysts. Kali Linux is another customized Linux distribution that has numerous tools that are designed for network security penetration testing.

#### Working in the Linux Shell
In Linux, the user communicates with the operating system through a GUI or a command-line interface (CLI), or shell. If a GUI is running, the shell is accessed through a terminal application such as xterm or gnome terminal. Linux commands are programs that perform a specific task. The man command, followed by a specific command, provides documentation for that command. It is important to know at least basic Linux commands, file and directory commands, and commands for working with text files. In Linux, everything is treated as if it were a file, including memory, disks, monitor, and directories.

#### Linux Servers and Clients
Servers are computers that have software installed that enables them to provide services to client computers across the network. Some services provide access to external resources such as files, email, and web pages, to clients upon request. Other services run internally and perform tasks such as log management, memory management, or disk scanning. To enable a computer to provide multiple services, ports are used. A port is a reserved network resource that "listens" for requests by clients. While the port number used by a service can be configured, most services listen on default "well-known" ports. Client software applications are designed to communicate with specific types of servers. Web browsers communicate with web servers using the HTTP protocol on port 80, while FTP clients communicate with FTP servers to transfer files.

#### Basic Server Administration
In Linux, servers are managed by using configuration files. Various settings can be modified and saved in configuration files. When a service is started, it looks at its configuration file(s) to know how it should run. There is no rule for the way configuration files are written, as formatting depends on the creator of the server software. Linux devices should be secured by using proven methods to protect the device and administrative access. This is known as hardening devices. One way to harden a device is to maintain passwords, configure enhanced login features, and implement secure remote login with SSH. It is also important to keep the operating system up to date. Other ways to harden a device include forcing periodic password changes, enforcing strong passwords, and preventing the reuse of passwords. Linux clients and servers use log files to record the operation of the system and important events. A number of different log files are maintained, including application logs, event logs, service logs, and system logs. Server logs record activities conducted by remote users who access system services. It is important to know the location of different logs in the Linux file system so that they can be accessed and monitored for problems.

#### The Linux File System
Linux supports a number of different file systems that vary by speed, flexibility, security, size, structure, logic, and more. Some of the file systems supported by Linux are ext2, ext3, ext4, NFS, and CDFS. File systems are mounted on partitions and accessed through mounting points, or directories. The mount command can be used to display details of the file systems that are currently mounted on a Linux computer. The root file system is represented by the "/" symbol and contains all of the files in the computer by default. Linux uses file permissions to control who is permitted to have different types of access to files and directories. Permissions include read (r), write (w), and execute (x). Files and directories have permissions assigned for users, groups, and others. The permissions for files and folders are displayed with the "ls -l" command, which also displays the links for a file. Hard links create another file with a different name that is linked to the same place in the file system. Only the root user can override file permissions. Changes to one of the hard-linked files are also made to the original file. Symbolic links, or symlinks, are similar to hard links, and a change to the linked file is reflected in the original file.

#### Working with Linux GUI
The X Windows, or X11, system is a basic software framework that includes functions for creating, controlling, and configuring a GUI in a point-and-click interface. Different vendors use the X Windows system to create different window manager GUIs for Linux. Examples of window managers are Gnome and KDE. The Ubuntu Linux distribution uses Gnome 3 by default. The Gnome 3 desktop consists of the Apps Menu, Ubuntu Dock, Top Bar, Calendar and System Message tray, the Activities area, and the Status Menu.

#### Working on a Linux Host
In order to install applications on Linux hosts, package managers are used. Packages are software applications and all of their supporting files. Different Linux distributions use different package managers. For example, Arch Linux uses pacman, Debian uses dpkg as the base package manager, and apt to communicate with dpkg. Ubuntu also uses apt. Package manager CLI commands are used to install, remove, and update software packages. Upgrade commands upgrade all currently installed packages. Threat actors can probe a device for open ports that are linked to out-of-date server processes, so it is important to keep the operating system and its components and applications up to date. The chkrootkit program is designed to detect rootkit malware, which is deep-level malware that is very difficult to detect and remove. Piping commands use the "|" symbol to chain different commands together by using the output of one command as the input for another.

### 2.8.2 Quiz: Linux Overview
- A system administrator issues the apt-get upgrade command on a Linux operating system. What is the purpose of this command?
    - Every application installed will update itself to the latest version.
- Which user can override file permissions on a Linux computer?
    - root user
- In the context of a Linux operating system, which command can be used to display the syntax and parameters for a specific command?
    - man
- What is a daemon?
    - A background process that runs without the need for user interaction
- Which type of tool is used by a Linux administrator to attack a computer or network to find vulnerabilities?
    - PenTesting
- Consider the result of the ls -l command in the Linux output below. What are the group file permissions assigned to the analyst.txt file?
  
   `-rwxrw-r-- sales staff 1028 May 28 15:50 analyst.txt`
   - read, write
- What is a benefit of Linux being an open source operating system?
    - Linux distribution source code can be modified and then recompiled.
- A system administrator issues the command ps on a server that is running the Linux operating system. What is the purpose of this command?
    - to list the processes currently running in the system
- What are three benefits of using symbolic links over hard links in Linux?
    - They can link to a directory.
    - They can show the location of the original file.
    - They can link to a file in a different file system.
- A technician has captured packets on a network that has been running slowly when accessing the internet. Which port number should the technician look for within the captured material to locate HTTP packets?
    - 80
- Which method can be used to harden a device?
    - Force periodic password changes.
- Which file system is the primary file system used by Apple in current Macintosh computers?
    - APFS
- Why would a rootkit be used by a hacker?
    - to gain access to a device without being detected
- Why is Kali Linux a popular choice in testing the network security of an organization?
    - It is an open source Linux security distribution containing many penetration tools.
- Which Linux command can be used to display the name of the current working directory?
    - pwd