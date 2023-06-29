import "cuckoo"

rule Adload {
  condition:
    cuckoo.genrex.atom(/(^|\\)(ControlOfs|WndProcPtr)0040000000000640$/) >= 2 or
    cuckoo.genrex.atom(/(^|\\)-%D4#!`````('&|B\*|N\*)````````P8!````````$/) >= 3 or
    cuckoo.genrex.atom(/(^|\\)-\x00%\x00D\x004\x00#\x00!\x00`\x00`\x00`\x00`\x00`\x00('\x00&|B\x00\*|N\x00\*)\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00P\x008\x00!\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00`\x00$/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\Downloader$/) >= 1 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\Iphlpapi\.dll$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)Software\\Downloader$/) >= 1 or
    cuckoo.registry.key_access(/(^|\\)S(OFTWARE\\Classes\\CLSID\\\{[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}\\(Merged|Shell)|oftware\\Classes\\CLSID\\\{[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}\\Shell)Folder$/) >= 45 or
    cuckoo.registry.key_access(/(^|\\)SYSTEM\\ControlSet001\\Control\\Nls\\CodePage\\4294967[0-9]{3}$/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)S(OFTWARE\\Classes\\(CLSID\\\{[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}|htmlfile\\shell\\printto\\command)|oftware\\Classes\\(CLSID\\\{[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}|htmlfile\\shell\\printto\\command))\\Supported(Protocols|Types)$/) >= 5 or
    cuckoo.genrex.resolved_api(/msvcrt\.dll!\?\?_U@YAPAXI@Z/) >= 1 or
    cuckoo.genrex.resolved_api(/apphelp\.dll!GetPermLayers/) >= 1
}