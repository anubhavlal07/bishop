"""Static knowledge the endpoint detectors match against.

Kept in one place, in code, deliberately: these lists are the part of Bishop a
detection engineer will actually want to argue with, and they should be
readable in a diff rather than buried in a data file.

Every entry is public knowledge — LOLBAS, the ATT&CK technique pages, and the
Windows binaries any Sysmon ruleset already watches. Nothing here is derived
from a customer environment.
"""

from __future__ import annotations

LOLBINS: dict[str, str] = {
    "rundll32.exe": "executes exported functions from an arbitrary DLL",
    "regsvr32.exe": "registers a DLL, and will fetch a remote scriptlet to do it",
    "mshta.exe": "runs HTML applications, including inline VBScript and JScript",
    "certutil.exe": "downloads and base64-decodes files as a side effect of certificate work",
    "bitsadmin.exe": "queues background transfers that survive reboots",
    "msbuild.exe": "compiles and runs inline C# from a project file",
    "installutil.exe": "runs installer classes, bypassing application control",
    "regasm.exe": "registers assemblies and runs their registration code",
    "regsvcs.exe": "registers COM+ services and runs their registration code",
    "cmstp.exe": "installs connection manager profiles that can run commands",
    "wmic.exe": "executes processes locally and remotely",
    "msiexec.exe": "installs packages, including from a URL",
    "cscript.exe": "runs Windows Script Host scripts",
    "wscript.exe": "runs Windows Script Host scripts",
    "forfiles.exe": "runs a command for each matched file",
    "pcalua.exe": "launches a program through the compatibility assistant",
    "odbcconf.exe": "loads a DLL through a response file",
    "hh.exe": "opens compiled help files, which can carry script",
    "ieexec.exe": "runs a managed application from a URL",
    "presentationhost.exe": "runs XBAP applications from a URL",
    "control.exe": "loads control panel applets, which are DLLs",
    "verclsid.exe": "verifies a COM object, instantiating it in the process",
    "print.exe": "copies a file, including to a remote path",
    "replace.exe": "copies files, including from a UNC path",
    "expand.exe": "expands cabinet files, including from a UNC path",
    "extrac32.exe": "extracts cabinet files, including from a UNC path",
    "findstr.exe": "searches files and can write output to an alternate data stream",
    "esentutl.exe": "copies files, including locked ones, and reads from UNC paths",
}

LOLBIN_ARGUMENT_TELLS: dict[str, tuple[tuple[str, str], ...]] = {
    "regsvr32.exe": (
        ("scrobj.dll", "loading the script COM object — the Squiblydoo pattern"),
        ("/i:http", "fetching a scriptlet over HTTP"),
        ("/i:ftp", "fetching a scriptlet over FTP"),
        ("-i:http", "fetching a scriptlet over HTTP"),
    ),
    "certutil.exe": (
        ("-urlcache", "using the URL cache as a downloader"),
        ("urlcache", "using the URL cache as a downloader"),
        ("-decode", "base64-decoding a payload"),
        ("decode", "base64-decoding a payload"),
        ("-encode", "base64-encoding a payload for transport"),
    ),
    "rundll32.exe": (
        ("javascript:", "executing inline JavaScript through the MSHTML protocol handler"),
        ("comsvcs.dll", "calling MiniDump through comsvcs — a credential-dumping path"),
        ("url.dll", "opening a URL or file through url.dll"),
        ("shell32.dll,control_rundll", "launching a control panel applet indirectly"),
        ("advpack.dll", "running an INF section through advpack"),
        ("setupapi.dll", "running an INF section through setupapi"),
        ("\\\\", "loading a DLL from a UNC path"),
    ),
    "mshta.exe": (
        ("javascript:", "executing inline JavaScript"),
        ("vbscript:", "executing inline VBScript"),
        ("http://", "fetching an HTA over HTTP"),
        ("https://", "fetching an HTA over HTTPS"),
    ),
    "bitsadmin.exe": (
        ("/transfer", "queueing a file transfer"),
        ("/create", "creating a transfer job"),
        ("/setnotifycmdline", "attaching a command that runs when the job completes"),
    ),
    "msiexec.exe": (
        ("http://", "installing a package from a URL"),
        ("https://", "installing a package from a URL"),
        ("/q", "installing silently"),
    ),
    "wmic.exe": (
        ("process call create", "creating a process, locally or on another host"),
        ("/node:", "targeting a remote host"),
    ),
    "msbuild.exe": (("/noconsolelogger", "suppressing output while compiling inline code"),),
    "esentutl.exe": (("/y", "copying a file, including a locked one"),),
}

EXPECTED_PARENTS: dict[str, frozenset[str]] = {
    "powershell.exe": frozenset(
        {
            "explorer.exe",
            "cmd.exe",
            "services.exe",
            "svchost.exe",
            "code.exe",
            "windowsterminal.exe",
            "powershell.exe",
            "pwsh.exe",
            "ssms.exe",
            "taskeng.exe",
            "sccm.exe",
            "ccmexec.exe",
        }
    ),
    "cmd.exe": frozenset(
        {
            "explorer.exe",
            "cmd.exe",
            "powershell.exe",
            "services.exe",
            "svchost.exe",
            "windowsterminal.exe",
            "taskeng.exe",
            "ccmexec.exe",
            "code.exe",
        }
    ),
    "wscript.exe": frozenset({"explorer.exe", "cmd.exe", "taskeng.exe"}),
    "cscript.exe": frozenset({"explorer.exe", "cmd.exe", "taskeng.exe"}),
    "rundll32.exe": frozenset({"explorer.exe", "svchost.exe", "services.exe", "dllhost.exe"}),
    "regsvr32.exe": frozenset({"explorer.exe", "cmd.exe", "msiexec.exe"}),
}

NEVER_SPAWNS_SHELL: dict[str, str] = {
    "winword.exe": "Word",
    "excel.exe": "Excel",
    "powerpnt.exe": "PowerPoint",
    "outlook.exe": "Outlook",
    "msaccess.exe": "Access",
    "onenote.exe": "OneNote",
    "acrord32.exe": "Acrobat Reader",
    "acrobat.exe": "Acrobat",
    "wordpad.exe": "WordPad",
    "eqnedt32.exe": "the Equation Editor",
    "mspub.exe": "Publisher",
    "visio.exe": "Visio",
}

SHELLS: frozenset[str] = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "bash.exe",
        "wsl.exe",
        "curl.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msiexec.exe",
    }
)

SYSTEM_BINARY_HOMES: dict[str, tuple[str, ...]] = {
    "svchost.exe": (r"c:\windows\system32", r"c:\windows\syswow64"),
    "lsass.exe": (r"c:\windows\system32",),
    "services.exe": (r"c:\windows\system32",),
    "csrss.exe": (r"c:\windows\system32",),
    "winlogon.exe": (r"c:\windows\system32",),
    "smss.exe": (r"c:\windows\system32",),
    "explorer.exe": (r"c:\windows",),
    "spoolsv.exe": (r"c:\windows\system32",),
    "taskhostw.exe": (r"c:\windows\system32",),
    "rundll32.exe": (r"c:\windows\system32", r"c:\windows\syswow64"),
    "powershell.exe": (
        r"c:\windows\system32\windowspowershell",
        r"c:\windows\syswow64\windowspowershell",
    ),
    "cmd.exe": (r"c:\windows\system32", r"c:\windows\syswow64"),
}

STAGING_DIRECTORIES: tuple[str, ...] = (
    r"c:\users\public",
    r"c:\programdata",
    r"c:\windows\temp",
    r"c:\temp",
    r"\appdata\local\temp",
    r"\appdata\roaming",
    r"\downloads",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
)

PERSISTENCE_REGISTRY_KEYS: dict[str, tuple[str, str]] = {
    r"\software\microsoft\windows\currentversion\run": ("T1547.001", "Run key"),
    r"\software\microsoft\windows\currentversion\runonce": ("T1547.001", "RunOnce key"),
    r"\software\microsoft\windows\currentversion\runservices": ("T1547.001", "RunServices key"),
    r"\software\microsoft\windows\currentversion\explorer\shell folders": (
        "T1547.001",
        "shell folders",
    ),
    r"\software\microsoft\windows nt\currentversion\winlogon": ("T1547.004", "Winlogon helper"),
    r"\software\microsoft\windows nt\currentversion\image file execution options": (
        "T1546.012",
        "image file execution options",
    ),
    r"\system\currentcontrolset\services": ("T1543.003", "service registration"),
    r"\software\classes\clsid": ("T1546.015", "COM hijack"),
    r"\software\microsoft\windows\currentversion\explorer\user shell folders": (
        "T1547.001",
        "user shell folders",
    ),
    r"\environment\userinitmprlogonscript": ("T1037.001", "logon script"),
}

CREDENTIAL_TOOLS: dict[str, str] = {
    "mimikatz": "Mimikatz",
    "sekurlsa": "a Mimikatz sekurlsa module command",
    "lsadump": "a Mimikatz lsadump module command",
    "procdump": "ProcDump",
    "pwdump": "pwdump",
    "gsecdump": "gsecdump",
    "wce.exe": "Windows Credential Editor",
    "nanodump": "nanodump",
    "dumpert": "Dumpert",
    "safetykatz": "SafetyKatz",
    "rubeus": "Rubeus",
    "lazagne": "LaZagne",
}

ARCHIVE_TOOLS: frozenset[str] = frozenset(
    {"7z.exe", "7za.exe", "rar.exe", "winrar.exe", "zip.exe", "tar.exe", "makecab.exe", "7z", "zip"}
)

ABUSED_HOSTING: frozenset[str] = frozenset(
    {
        "pastebin.com",
        "hastebin.com",
        "ghostbin.com",
        "transfer.sh",
        "anonfiles.com",
        "file.io",
        "temp.sh",
        "0x0.st",
        "discord.com",
        "cdn.discordapp.com",
        "raw.githubusercontent.com",
        "gist.githubusercontent.com",
        "ngrok.io",
        "trycloudflare.com",
        "telegram.org",
        "api.telegram.org",
    }
)
