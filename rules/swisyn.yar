import "cuckoo"

rule Swisyn
{
  condition:
    cuckoo.genrex.atom(/(^|\\)Enigma(ControlOfs|WndProcPtr)00400000000004DC$/) >= 2 or
    cuckoo.filesystem.file_access(/(^|\\)(C:\\Windows\\(resources|system)\\svchost(\.EN)?|C:\\Windows\\svchost\.exe)\.(DLL|EN|ENG|cfg|exe)$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\system\\explorer\.(ENG(G)?|exe)$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Program Files\\ZoneWard\\Data\\Launcher\\GRAFICOS\\|Windows\\winsxs\\FileMaps\\program_files_zoneward_data_inter)face(_d147ed031ee8948c\.cdf-ms|book[01]\.(bmp|psd))$/) >= 4 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\Parameters\.ini$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\eajJNoiqqgx\.(EN|ENG|exe)$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\mizKwOWo\.(EN|ENG|exe)$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\ntERbiyhyi\.(EN|ENG|exe)$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\otnhijySmuxw\.(EN|ENG|exe)$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\rFwaeuzWe\.(EN|ENG|exe)$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\rnpuuSwqqj\.(EN|ENG|exe)$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\sYeesEYzoZ\.(EN|ENG|exe)$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\uqsdnPmuw\.(EN|ENG|exe)$/) >= 3 or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Explorer$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)S(OFTWARE|oftware)\\Microsoft\\Windows\\CurrentVersion\\Run\\help$/) >= 2 or
    cuckoo.registry.key_access(/(^|\\).{117,127}\.(OZJ|bmd)$/) >= 13 or
    cuckoo.registry.key_access(/(^|\\)S(OFTWARE|oftware)\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TypeAhead$/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Microsoft\\CTF\\Compatibility\\Steam key 2018s(jvjvsv)?\.exe$/) >= 2 or
    cuckoo.sync.mutex(/(^|\\)explorer\.exeM_[0-9]{4}_$/) >= 3 or
    cuckoo.genrex.resolved_api(/gdi32\.dll!(GdiDrawStream|ResetDCW)/) >= 1 or
    cuckoo.genrex.resolved_api(/(dbghe|imageh)lp\.dll!SymGet(ModuleInfo(W)?|Options|SymFromAddr)/) >= 5 or
    cuckoo.genrex.semaphore(/(^|\\)C:\?WINDOWS\?SYSTEM(32)?\?EXPLORER\.EXE$/) >= 1 or
    cuckoo.genrex.semaphore(/(^|\\)C:\?WINDOWS\?SPOOLSW\.EXE$/) >= 1 or
    cuckoo.genrex.semaphore(/(^|\\)C:\?USERS\?SUSAN\?APPDATA\?LOCAL\?TEMP\?(FKIPDDNJHXI|JEXQAQMJNZE|XIVUNVAGEII|YJYNPVYFEOD)\.EXE$/) >= 1 or
    cuckoo.genrex.semaphore(/(^|\\)C:\?USERS\?SUSAN\?APPDATA\?LOCAL\?TEMP\?(ICYHYOIBQS|OWQUWRIOFO|UBVLHAIHL)\.EXE$/) >= 1
}


