import "cuckoo"

rule Ursnif {
  condition:
    cuckoo.genrex.atom(/(^|\\)-\x00%\x00D\x004\x00#\x00!\x00`\x00`\x00`\x00`\x00`\x00.{22,23}\x00!\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00$/) >= 1 or
    cuckoo.genrex.atom(/(^|\\)-\x00%\x00D\x004\x00#\x00!\x00`\x00`\x00`\x00`\x00`\x00.{2,3}\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x000\x00;\x00!\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00$/) >= 6 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\System32\\C_1252\.NLS$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)msl0$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)sl55[0-9a-f]$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\System32\\(WindowsPowerShell\\v1\.0|wbem))\\a CKrhUJtz$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\System32\\(WindowsPowerShell\\v1\.0|wbem))\\dasipamiji motepicuwafakucebulokedidasaza mohifevipebizojuzomayolenako kiwoboyayacohemexoke dapode\\gimayanosepedugipuluyoculedepu lukilaborofukaropukogo yuruyajibowodiduku$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Users\\[^\\]+\\AppData\\Local\\Temp|Windows\\System32\\(WindowsPowerShell\\v1\.0|wbem))\\ewqzafg\.dll$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Program Files\\ICare Recovery\\(init|proc)_file(DD|_proc)\.dll$/) >= 2 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Program Files\\(ICare Recovery\\(Microsoft\.VC80\.(CRT|MFC)|iCDR\.exe\.intermediate)\.|Mozilla Firefox\\gmp-clearkey\\0\.1\\)manifest(\.json)?$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)Software\\AppDataLow\\Software\\Microsoft\\[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\\Client$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)S-1-5-21-962146886-2531488156-1783242634-1000\\Software\\Microsoft\\Internet Explorer\\Main\\IE(1)?[08]RunOnceLastShown$/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)(SystemFileAssociations\\)?\.list$/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)S-1-5-21-962146886-2531488156-1783242634-1000\\Software\\Microsoft\\Internet Explorer\\Main\\Check_Associations$/) >= 1 or
    cuckoo.sync.mutex(/(^|\\)FollowcoatYard$/) >= 1 or
    cuckoo.genrex.resolved_api(/shell32\.dll!#92/) >= 1 or
    cuckoo.genrex.resolved_api(/(imm32\.dll!Imm|ntdll\.dll!RtlDelete)Regist(erWordA|ryValue)/) >= 1 or
    cuckoo.genrex.resolved_api(/(dbghelp\.dll!SymRegisterFunc|ntdll\.dll!RtlRemoveVectoredExcep)tion(EntryCallback|Handler)/) >= 1 or
    cuckoo.genrex.resolved_api(/kernel32\.dll!#0/) >= 1 or
    cuckoo.genrex.resolved_api(/powrprof\.dll!IsPwrS(hutdown|uspend)Allowed/) >= 2 or
    cuckoo.genrex.resolved_api(/ntdll\.dll!RtlRemoveVectoredExceptionHandler/) >= 1 or
    cuckoo.genrex.semaphore(/(^|\\)IsoScope_1e8_IEFrame!GetAsyncKeyState(Query|Reply)$/) >= 2
}