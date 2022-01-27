/*
    A rule to detect functionstomping based on imports.
    Author: Ido Veltzman (Idov31)
    Date: 28-01-2022
*/

rule FunctionStomping {
    meta:
        description = "A rule to detect functionstomping."
        author = "Idov31"
        date = "2022-01-28"
    strings:
        $s0 = "OpenProcess" ascii
        $s1 = "EnumProcessModules" fullword ascii
        $s2 = "GetModuleFileName" ascii
        $s3 = "GetProcAddress" fullword ascii
        $s4 = "VirtualProtect" ascii
        $s5 = "WriteProcessMemory" fullword ascii

    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}