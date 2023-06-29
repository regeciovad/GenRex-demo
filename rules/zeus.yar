import "cuckoo"

rule Zeus
{
  condition:
    cuckoo.genrex.atom(/(^|\\)-\x00%\x00D\x004\x00#\x00!\x00`\x00`\x00`\x00`\x00`\x00[A-Z]\x00\+\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x000\x007\x00!\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00$/) >= 3 or
    cuckoo.genrex.atom(/(^|\\)-\x00%\x00D\x004\x00#\x00!\x00`\x00`\x00`\x00`\x00`\x00.{3}\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00(0\x00[8;]|P\x00[57]|`\x00[69])\x00!\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00$/) >= 1 or
    cuckoo.genrex.atom(/(^|\\)-\x00%\x00D\x004\x00#\x00!\x00`\x00`\x00`\x00`\x00`\x00.{23}\x00!\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00$/) >= 1 or
    cuckoo.genrex.atom(/(^|\\)-%D4#!`````[\-3467:]\*````````08!````````$/) >= 6 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\TOOLS\\execute\.exe$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\System32\\ntos\.exe$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\[0-9A-Za-z]{4,6}\\msvcr100\.dll$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\tmp_[0-9a-f]{8}\.bat$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\887[07]21875\.log$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\IEDownloadHistory$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)(C:\\Windows\\(System32\\)?|\\\?\\C:\\Windows\\System32\\)Tasks\\tmp4591(\.job)?$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\OEgLqAYeukPU(\.ex_|\.exe)$/) >= 2 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\UvAkqiSs(\.exe\.Config|\.exe)$/) >= 2 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\oySDkybgJaJ(\.ex_|\.exe)$/) >= 2 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\ycbBYabv(\.ex_|\.exe)$/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)Software\\WINE$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)software\\microsoft\\windows nt\\currentversion\\winlogon$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\System$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)S(OFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0|oftware\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\[0-9])\\1A02$/) >= 4 or
    cuckoo.registry.key_access(/(^|\\)\xE3\x84\xB4\xE3\x90\xB2$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)Software\\Local AppWizard-Generated Applications\\(Cell|oger)\\Recent File List$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Classes\\MfcAtl\.ObjectOne\\(CLSID\\)?\(Default\)$/) >= 2 or
    cuckoo.sync.mutex(/(^|\\)Sandboxie_SingleInstanceMutex_Control$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)__SYSTEM__64AD0625__$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)MSCTF\.CtfMonitorInstMutexwin_[0-9]{2}$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)_AVIRA_2109$/) >= 1 or
    cuckoo.genrex.resolved_api(/ntdll\.dll!(RtlUserThreadStart|ZwSaveMergedKeys)/) >= 1 or
    cuckoo.genrex.resolved_api(/[0-9a-f]{3,6}\.tmp!NtClose/) >= 1 or
    cuckoo.genrex.resolved_api(/(ntdll\.dll!Ldr|shlwapi\.dll!Path)Find(EntryForAddress|SuffixArrayW)/) >= 1 or
    cuckoo.genrex.resolved_api(/shlwapi\.dll!PathIsURL[AW]/) >= 1 or
    cuckoo.genrex.resolved_api(/kernel32\.dll!(Crea|Wri)teConsole(OutputCharacterW|ScreenBuffer)/) >= 2 or
    cuckoo.genrex.semaphore(/(^|\\)IsoScope_a30_IEFrame!GetAsyncKeyState(Query|Reply)$/) >= 2
}