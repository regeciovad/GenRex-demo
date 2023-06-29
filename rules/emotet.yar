import "cuckoo"

rule Emotet
{
  condition:
    cuckoo.genrex.atom(/(^|\\)-\x00%\x00D\x004\x00#\x00!\x00`\x00`\x00`\x00`\x00`\x00.{23}\x00!\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00$/) >= 1 or
    cuckoo.genrex.atom(/(^|\\)QwQkZbJDU$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\System32\\bundle(member|shims)\.exe$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\System32\\captureextid\.exe$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\System32\\PartitionClu\.exe$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\System32\\eventgdi\.exe$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\System32\\(WindowsPowerShell\\v1\.0|wbem))\\CoFENIFFkL$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\(Microsoft\\Windows\\Start Menu\\Programs\\Startup\\)?BrightenStyle(\.lnk|\\BrightenStyle\.exe:Zone\.Identifier)$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\System32\\(WindowsPowerShell\\v1\.0|wbem))\\AGfnZlgbcg9QQvb6M(\.\*)?$/) >= 6 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\iDCTKULkoxfb\.thf$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\doifughsg siodufhg sdfoughjsiopdfughj$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\System32\\(WindowsPowerShell\\v1\.0|wbem))\\Vg vRDQgyO$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\System32\\(WindowsPowerShell\\v1\.0|wbem))\\wRE CHzlHE$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\Y4CWqssFF4NtlcJIfu\.cat$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\DowLtrtyPZCa\.asn$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\osudhfa sdiufh aoisduhfo$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\WindowsNMq8H0jfa\.txt$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\System32\\FuncEmboss\.exe$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\System32\\(WindowsPowerShell\\v1\.0|wbem))\\M0pN\?1e-aY@QP25R$/) >= 3 or
    cuckoo.registry.key_access(/(^|\\)SYSTEM\\ControlSet001\\services\\[0-9a-z]{12,14}\\Environment$/) >= 1 or
    cuckoo.genrex.resolved_api(/advapi32\.dll!TreeSetNamedSecurityInfoW/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)Software\\(Local AppWizard-Generated Applications|Microsoft\\Windows\\CurrentVersion\\Run)\\4152a047e881d4b34854eaf6fe7a109b$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)PEM[0-9A-F]{2,3}$/) >= 2 or
    cuckoo.sync.mutex(/(^|\\)NxCDCBD7BE$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)D6BB2EC6RM$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)N5fG0lxr5znuHf8xGWulbG_6$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)DVXBiHAOp30SY3d8qLhr_3$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)Em2m69YbqoJaZ$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)FBhEggk2yZd4$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)(Identities\\\{[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}\\A|Software\\Microsoft\\Office\\Common\\D6BB2EC6\\D6BB2EC6PS)\\\(Default\)$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Microsoft\\Tracing\\(ahnnihygQrmb_RASAPI32\\(Enable)?|mzjfFbrjyk_RASAPI32\\Enable|xbrxJhLwdu_RASAPI32\\Enable)ConsoleTracing(Mask)?$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)Software\\Local AppWizard-Generated Applications\\MFCBind\\Recent File List\\File[0-9]$/) >= 4 or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\BcThuovQn\.exe$/) >= 2 or
    cuckoo.genrex.resolved_api(/user32\.dll!SetPhysicalCursorPos/) >= 1 or
    cuckoo.genrex.resolved_api(/ntdll\.dll!(cos|sin)/) >= 2 or
    cuckoo.genrex.semaphore(/(^|\\)C:\?USERS\?SUSAN\?APPDATA\?(LOCAL\?(4152A047E881D4B34854EAF6FE7A109B|\{[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\})|ROAMING\?BRIGHTENSTYLE\?BRIGHTENSTYLE)\.EXE$/) >= 1
}
