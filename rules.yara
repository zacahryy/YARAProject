import "pe"

rule MalwareDetection {

    meta:
        author = "Zach Faulkner"
        date = "12/12/2024"
        reference = "CPSC458 Exercise 4"
    
    strings:
        $a1 = "http://c2-7f000001.nip.io/" fullword ascii
        $b1 = "CreateMutexA" fullword ascii
        $c1 = "@Out of bounds:" fullword ascii
        $d1 = "persist.exe" fullword ascii
        $e1 = "(5.c-" fullword ascii
    
    condition:
        uint16(0) == 0x5A4D
        and ($a1 and $e1) or ($b1 and $c1 and $d1)
        and filesize > 5080000
}