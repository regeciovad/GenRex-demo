import "cuckoo"

rule Qakbot
{
  condition:
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\(AppData\\Local\\Temp\\~)?onayjeqh\.(tmp|wpl)$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\INTERNAL\\__empty$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\ProgramData\\FilesystemMonitor(\\fsmonitor\.(dll|ini))?$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\ProgramData\\FilesystemMonitor\\fsmonitor\.(dll|ini)$/) >= 2 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\ProgramData\\FilesystemMonitor\\fsmonitor\.dll\.(12[34]\.M|2\.M|m)anifest$/) >= 4 or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-962146886-2531488156-1783242634-50[01]$/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)Volatile Environment\\USER(DOMAIN|NAME)$/) >= 2 or
    cuckoo.sync.mutex(/(^|\\)oouoma$/) >= 1 or
    cuckoo.genrex.resolved_api(/msvcrt\.dll!_HUGE/) >= 1
}