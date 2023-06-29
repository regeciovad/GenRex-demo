import "cuckoo"

rule HarHar
{
  condition:
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\config(-nkxmr)?\.json$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\.json$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)S(OFTWARE\\Microsoft\\(Internet Explorer\\MAIN\\FeatureControl\\FEATURE_(LOCALMACHINE|PROTOCOL)_LOCKDOWN|Windows\\CurrentVersion\\ShellCompatibility\\Applications)|oftware\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_LOCALMACHINE_LOCKDOWN)\\leQaazfIgr\.exe$/) >= 4 or
    cuckoo.genrex.resolved_api(/ws2_32\.dll!WSADuplicateSocketW/) >= 1
}