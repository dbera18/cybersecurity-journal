rule Suspicious_PowerShell_Download
{
    meta:
        author = "Dev Bera"
        description = "Encoded PowerShell combined with a web download"
    strings:
        $enc = "powershell -enc" nocase
        $web = "Invoke-WebRequest" nocase
    condition:
        $enc and $web
}

rule Ransom_Note_Keywords
{
    meta:
        author = "Dev Bera"
        description = "Common ransom-note phrases"
    strings:
        $a = "files are encrypted" nocase
        $b = "bitcoin" nocase
        $c = "DECRYPT"
    condition:
        2 of them
}