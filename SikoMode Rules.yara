rule SikoMode {
    
    meta: 
        last_updated = "2024-12-31"
        author = "thorax90"
        description = "SikoMode Detection Rules"

    strings:
        // Fill out identifying strings and other criteria
        $string1 = "password.txt" ascii
        $string2 = "nim" ascii
        $string3 = "SikoMode"
        $string4 = "houdini"
        $string5 = "cdn.altimiter.local"
        $PE_magic_byte = "MZ"
        
    condition:
        // Fill out the conditions that must be met to identify the binary
        $PE_magic_byte at 0 and 
        ($string1 and $string2 and $string3 and $string4) or
        $string5
}
