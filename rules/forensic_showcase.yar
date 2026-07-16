/*
    ===================================================================================
    OpenForensic Enterprise Threat Hunting & IR Showcase Rules (YARA-X)
    ===================================================================================
    Description : Professional YARA ruleset designed to showcase real-time memory
                  and disk image scanning capabilities within OpenForensic v2.1.0.
    Author      : OpenForensic IR Team
    Updated     : 2026-07-16
    Targets     : Ransomware Notes, Credential Dumpers, Webshells, C2 Beacons,
                  Injected PE Executables, and Standard Forensic Test Vectors.
    ===================================================================================
*/

rule Demo_Ransomware_Note_Patterns : Ransomware Critical Alert
{
    meta:
        author = "OpenForensic IR Team"
        description = "Detects common ransomware extortion notes, shadow copy deletion commands, and TOR payment instructions"
        severity = "High"
        mitre_attck = "T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)"
    strings:
        $note1 = "Your files have been encrypted" nocase ascii wide
        $note2 = "All your documents, photos, databases have been locked" nocase ascii wide
        $note3 = "To decrypt your files you need to purchase our special key" nocase ascii wide
        $note4 = ".onion/" ascii wide
        $cmd1  = "vssadmin delete shadows /all /quiet" nocase ascii wide
        $cmd2  = "wmic shadowcopy delete" nocase ascii wide
        $cmd3  = "bcdedit /set {default} recoveryenabled No" nocase ascii wide
    condition:
        any of ($note*) or any of ($cmd*)
}

rule Demo_Credential_Dumper_Mimikatz : CredentialAccess Critical Alert
{
    meta:
        author = "OpenForensic IR Team"
        description = "Detects in-memory signatures, command-line arguments, and modules associated with Mimikatz credential dumping"
        severity = "Critical"
        mitre_attck = "T1003.001 (OS Credential Dumping: LSASS Memory)"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase ascii wide
        $m2 = "lsadump::sam" nocase ascii wide
        $m3 = "lsadump::lsa /patch" nocase ascii wide
        $m4 = "privilege::debug" nocase ascii wide
        $m5 = "gentilkiwi" ascii wide
        $m6 = "mimikatz" nocase ascii wide
        $s1 = "wdigest.dll" nocase ascii wide
        $s2 = "tspkg.dll" nocase ascii wide
    condition:
        2 of ($m*) or ($m6 and any of ($s*))
}

rule Demo_Webshell_PHP_CmdExec : Persistence Webshell High
{
    meta:
        author = "OpenForensic IR Team"
        description = "Detects obfuscated and direct PHP command execution webshell payloads inside web server logs or disk images"
        severity = "High"
        mitre_attck = "T1505.003 (Server Software Component: Web Shell)"
    strings:
        $w1 = "eval(base64_decode(" ascii
        $w2 = "$_REQUEST['cmd']" ascii
        $w3 = "$_POST['exec']" ascii
        $w4 = "system($_GET[" ascii
        $w5 = "passthru($_POST[" ascii
        $w6 = "shell_exec(" ascii
        $w7 = "fsockopen(" ascii
    condition:
        any of ($w*)
}

rule Demo_CobaltStrike_Beacon_Memory : C2 Beacon Critical
{
    meta:
        author = "OpenForensic IR Team"
        description = "Detects Cobalt Strike Reflective DLL loader strings, named pipe patterns, and post-exploitation configs in memory"
        severity = "Critical"
        mitre_attck = "T1059 (Command and Scripting Interpreter), T1055 (Process Injection)"
    strings:
        $cs1 = "ReflectiveLoader" ascii
        $cs2 = "%s as %s\\%s: %d" ascii
        $cs3 = "beacon.dll" nocase ascii wide
        $pipe1 = "\\\\.\\pipe\\MSSE-" ascii wide
        $pipe2 = "\\\\.\\pipe\\postex_" ascii wide
        $useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" ascii wide
    condition:
        ($cs1 and $cs2) or any of ($pipe*) or ($cs3 and $useragent)
}

rule Demo_Embedded_PE_Binary_In_Memory : DefenseEvasion Injection Medium
{
    meta:
        author = "OpenForensic IR Team"
        description = "Detects unmapped or injected Portable Executable (PE) headers and remote thread injection APIs within memory buffers"
        severity = "Medium"
        mitre_attck = "T1055.001 (Dynamic-link Library Injection), T1055.002 (Portable Executable Injection)"
    strings:
        $mz   = "MZ"
        $dos  = "This program cannot be run in DOS mode" ascii
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtUnmapViewOfSection" ascii
    condition:
        $mz at 0 and $dos and 2 of ($api*)
}

rule Demo_Exfiltration_Staging_Commands : Exfiltration Medium
{
    meta:
        author = "OpenForensic IR Team"
        description = "Detects command-line activity indicating bulk archive creation with password protection or cloud sync staging"
        severity = "Medium"
        mitre_attck = "T1560.001 (Archive via Utility), T1567.002 (Exfiltration to Cloud Storage)"
    strings:
        $ex1 = "7z a -p" nocase ascii wide
        $ex2 = "rar a -hp" nocase ascii wide
        $ex3 = "rclone copy " nocase ascii wide
        $ex4 = "rclone sync " nocase ascii wide
        $ex5 = "megacli put " nocase ascii wide
    condition:
        any of ($ex*)
}

rule Demo_Windows_System_Triage_Artifacts : Triage Baseline Info
{
    meta:
        author = "OpenForensic IR Team"
        description = "Matches standard Windows operating system artifacts, registry paths, and HTTP headers to verify baseline scanning during live demos"
        severity = "Informational"
    strings:
        $t1 = "Microsoft Windows" ascii wide
        $t2 = "CurrentControlSet\\Services" ascii wide
        $t3 = "HTTP/1.1 200 OK" ascii
        $t4 = "NTFS" ascii wide
    condition:
        any of ($t*)
}

rule Demo_EICAR_Standard_Test_Signature : AntivirusTest Verification
{
    meta:
        author = "European Institute for Computer Antivirus Research (EICAR)"
        description = "Standard EICAR benign test string for verifying positive scanner alert firing without exposing systems to live malware"
        severity = "Informational"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}
