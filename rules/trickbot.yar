import "cuckoo"

rule Trickbot {
  condition:
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\System32\\Tasks\\M(icrosoft\\Windows\\Media Center\\(Pvr(Recovery|Schedule)|SqlLiteRecovery)Task|sSystemWatcher)$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\(GoogleS|locals)ervice$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\freenet$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\ProgramData\\Time Manager$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\System32\\(WindowsPowerShell\\v1\.0|wbem)\\Set-MpPreference\.\*$/) >= 2 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\diskcheck$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\mstools$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\extvisual$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\programdata\\(a49f132b8b\\smjalrc|b46d16ec5a\\gkmoov)\.exe:Zone\.Identifier$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\(Local\\Temp|Roaming\\coplane)\\eYRiugviixU(\.exe)?\.(cfg|exe)$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\(Local\\Temp|Roaming\\wsxmail)\\tfniYbyxuoa(\.exe)?\.(cfg|exe)$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\FTPGetter$/) >= 2 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\gdfsddscvds\.(INI|exe)$/) >= 2 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\(Ethereum|monero-project)\\keystore$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\services(.{18,21})?$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)S(OFTWARE\\Microsoft\\Windows (Defender Security Center\\Notifi|NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\(Microsoft\\Windows\\Lo|System Health Appli))ca|oftware\\Microsoft\\CTF\\CUAS\\NonEAComposi)tion(s)?$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)Software\\Number$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)Software\\Classes\\tdesktop\.tg\\shell\\open\\command$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\Windows( NT\\CurrentVersion\\AppCompatFlags\\Custom\\|\\CurrentVersion\\Run\\Windows )Time( Manager|Manager\.exe)$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\Disable(IOAVProtection|OnAccessProtection )$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\RUNDLL32\.exe$/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Microsoft\\CTF\\Compatibility\\fdfbvd\.exe$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)S(OFTWARE\\Microsoft\\Internet Explorer\\MAIN|oftware\\Microsoft\\Internet Explorer\\Main)\\FeatureControl\\FEATURE_LOCALMACHINE_LOCKDOWN\\oocYHledoGva\.exe$/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\wgvrweqrv\.exe$/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)Software\\VB and VBA Program Settings\\yDbA(eoYn|fpZo)\\Options\\Show Tips at Startup$/) >= 2  or
    cuckoo.registry.key_access(/(^|\\)steampath$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)10195952654[89]32832$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)WEB_ENGINE$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)MAIL_PROVIDER$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)TrickBot$/) >= 1 or
    cuckoo.genrex.resolved_api(/redomsi\.dll!(FPEfuncCALL|OperatorCode)/) >= 2 or
    cuckoo.genrex.resolved_api(/ncrypt\.dll!NCrypt(DeleteKey|FreeObject|ImportKey)/) >= 3 or
    cuckoo.genrex.resolved_api(/msvcrt\.dll!(_localtime64|wcsftime)/) >= 2 or
    cuckoo.genrex.resolved_api(/ncrypt\.dll!NCryptOpenStorageProvider/) >= 1 or
    cuckoo.genrex.semaphore(/(^|\\)C:\?USERS\?SUSAN\?APPDATA\?ROAMING\?(LOGMONITOR\?YIIGEMGBEYA|WINAPP\?VKKSHDZAU)\.EXE$/) >= 1 
}