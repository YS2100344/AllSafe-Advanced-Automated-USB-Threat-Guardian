rule SuspiciousExecutable {
    meta:
        description = "Detects suspicious executable files with basic malware indicators"
        author = "Yousef"
        date = "2025"
    strings:
        $hex_pattern = { 4D 5A }  // MZ header for Windows executables
        $packer = { 50 4B 03 04 }  // ZIP/Packed file indicator
        $upx_header = "UPX!"  // UPX packer indicator
        $suspicious_imports = /CreateRemoteThread|VirtualAlloc|WriteProcessMemory|ShellExecute/i
        $malicious_strings = /reverse_tcp|meterpreter|shellcode|keylogger|ransomware/i
        $suspicious_extensions = /\.exe$|\.dll$|\.bat$|\.cmd$|\.ps1$|\.vbs$|\.js$|\.jar$|\.class$|\.py$|\.sh$/i
    condition:
        ($hex_pattern or $suspicious_extensions) and 
        (any of ($suspicious_imports, $malicious_strings) or $packer or $upx_header)
}

rule EICARTestFile {
    meta:
        description = "Detects the EICAR test file"
        author = "Yousef"
        date = "2025"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule KnownMalwareSignature {
    meta:
        description = "Detects known malware signatures and patterns"
        author = "Yousef"
        date = "2025"
    strings:
        $ransomware_ext = /\.wannacry$|\.wcry$|\.wncry$|\.wncryt$|\.locked$|\.encrypted$/i
        $ransom_note = "YOUR FILES HAVE BEEN ENCRYPTED" wide ascii
        $malware_families = /wannacry|petya|notpetya|ryuk|conti|emotet|trickbot|qakbot/i nocase
        $suspicious_patterns = /cmd\.exe|powershell|wscript|cscript|regsvr32|rundll32|mshta|certutil|bitsadmin/i
        $malicious_apis = {
            48 83 EC 20 48 89 5C 24 30 48 89 6C 24 38 48 89 74 24 40 57 48 83 EC 20 48 8B D9 
            48 8B 0D ?? ?? ?? ?? 48 8B F2 48 8B F9 FF 15
        }  // Common malware API pattern
    condition:
        any of ($ransomware_ext, $ransom_note, $malware_families, $suspicious_patterns) or
        $malicious_apis
}

rule SuspiciousScript {
    meta:
        description = "Detects suspicious script content"
        author = "Yousef"
        date = "2025"
    strings:
        $encoded_powershell = /powershell.*(-enc|-e|-encodedcommand)\s+[A-Za-z0-9+\/]{50,}=/i
        $malicious_cmdline = /cmd\.exe.*(\/c|\/k)\s+(powershell|certutil|bitsadmin|reg|sc)\s+/i
        $obfuscation = /\[char\]\(\d{2,3}\)|\[byte\]\(\d{2,3}\)|\[int\]\(\d{2,3}\)/
        $download_exec = /Invoke-(WebRequest|RestMethod|Expression)|wget|curl|DownloadString|DownloadFile/i
        $persistence = /New-Service|sc create|schtasks|at \d{2}:\d{2}/i
        $suspicious_commands = /net\s+user|net\s+localgroup|net\s+group|reg\s+add|reg\s+delete|netsh/i
    condition:
        ($encoded_powershell and ($download_exec or $persistence)) or
        ($malicious_cmdline and $obfuscation) or
        (all of ($download_exec, $persistence)) or
        $suspicious_commands
}

// Whitelist common legitimate patterns
rule Whitelist {
    meta:
        description = "Whitelist for common legitimate files"
    strings:
        $pdf_header = { 25 50 44 46 }  // %PDF
        $doc_header = { D0 CF 11 E0 }  // DOC/DOCX
        $txt_content = /Copyright|License|README|CHANGELOG|VERSION/i
        $code_comment = /\/\*|\*\/|\/\/|#|--|rem\s/
        $jpeg_header = { FF D8 FF E0 }
        $png_header = { 89 50 4E 47 }
        $gif_header = { 47 49 46 38 }
    condition:
        any of them and not SuspiciousExecutable and not KnownMalwareSignature and not SuspiciousScript and not EICARTestFile
}
