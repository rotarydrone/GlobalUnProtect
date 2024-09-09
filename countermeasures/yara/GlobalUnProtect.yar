rule HackTool_MSIL_GLOBALUNPROTECT_GUID
{
    meta:
        description = "This rule looks for the ProjectGuid corresponding to the GlobalUnprotect.exe assembly"
        rev = 1
        author = "rotarydrone"
    strings:
        $typelibguid1 = "E9172085-1595-4E98-ABF8-E890D2489BB5" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}
rule HackTool_MSIL_GLOBALUNPROTECT_STRINGS
{
    meta:
        description = "This rule looks for string references to to registry keys and XML paths in GlobalProtect .dat files referenced by the GlobalUnProtect.exe tool."
        rev = 1
        author = "rotarydrone"
    strings:
		$s1 = "//policy/agent-ui/uninstall-passwd" ascii nocase wide
        $s2 = "//policy/portal-prelogonuserauthcookie" ascii nocase wide
		$s3 = "Software\\Palo Alto Networks\\GlobalProtect\\Settings" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}