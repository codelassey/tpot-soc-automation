/*
 * T-Pot Threat Intelligence — YARA Detection Rules
 * Source: https://github.com/codelassey
 * So, with intel from the honeypot logs, I came up with these rulees
 * I plan to expand this tho
 * Usage: yara -r tpot-rules.yar /path/to/scan
 *        Or I can load into my EDR platform.. will work a prooject on that
 */

rule TPOT_mdrfckr_SSH_Backdoor
{
    meta:
        description = "mdrfckr cryptomining campaign SSH authorized_keys backdoor"
        author      = "Prince Lassey"
        date        = "2026-05-27"
        sha256      = "a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2"
        mitre       = "T1098.004"
        severity    = "CRITICAL"
        reference   = "Cowrie had 10 downloads"
    strings:
        $key_comment = "mdrfckr" ascii
        $pub_key     = "AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7" ascii
        $chattr      = "chattr -ia .ssh" ascii
    condition:
        $key_comment or $pub_key or $chattr
}

rule TPOT_Trojanized_sshd_CoinMiner
{
    meta:
        description = "Trojanized sshd binary with embedded CoinMiner"
        author      = "Prince Lasssey"
        date        = "2026-05-27"
        sha256      = "062ba629c7b2b914b289c8da0573c179fe86f2cb1f70a31f9a1400d563c3042a"
        mitre       = "T1554, T1496, T1547"
        severity    = "CRITICAL"
        filename    = "malware_sshd"
    strings:
        $name    = "malware_sshd" ascii
        $miner   = "CoinMiner" ascii nocase
        $ssh_str = "OpenSSH" ascii
    condition:
        $name or ($ssh_str and $miner)
}

rule TPOT_ADB_Nohup_Dropper
{
    meta:
        description = "ADB dropper masquerading as nohup — drops 20 files"
        author      = "Prince Lassey"
        date        = "2026-05-27"
        sha256      = "d7188b8c575367e10ea8b36ec7cca067ef6ce6d26ffa8c74b3faa0b14ebb8ff0"
        mitre       = "T1036.005, T1105, T1570"
        severity    = "HIGH"
        arch        = "ARM ELF"
    strings:
        $adb_path1 = "/data/local/tmp/trinity" ascii
        $adb_path2 = "/data/local/tmp/ufo.apk" ascii
        $adb_path3 = "/data/local/tmp/.b" ascii
        $adb_path4 = "/data/local/tmp/nohup" ascii
    condition:
        2 of ($adb_path1, $adb_path2, $adb_path3, $adb_path4)
}

rule TPOT_UFO_Miner_APK
{
    meta:
        description = "com.ufo.miner Android cryptominer APK"
        author      = "Prince Lassey"
        date        = "2026-05-27"
        sha256      = "0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257"
        mitre       = "T1496, T1422, T1533"
        severity    = "HIGH"
    strings:
        $pkg     = "com.ufo.miner" ascii
        $c2_1    = "coinhive.com" ascii
        $c2_2    = "ws015.coinhive.com" ascii
        $miner   = "CoinHive" ascii nocase
    condition:
        $pkg or ($c2_1 and $c2_2) or ($pkg and $miner)
}

rule TPOT_XMRig_CLI_Miner
{
    meta:
        description = "XMRig miner with explicit CLI pool/wallet arguments"
        author      = "Prince Lassey"
        date        = "2026-05-27"
        sha256      = "467c7ed2badbf51cf9383eda657a9470511b7bdd66962503bf230d503f727aa8"
        mitre       = "T1496"
        severity    = "HIGH"
        yara_source = "PUA_Crypto_Mining_CommandLine_Indicators"
    strings:
        $pool    = "--pool" ascii
        $wallet  = "--wallet" ascii
        $threads = "--threads" ascii
        $xmrig   = "xmrig" ascii nocase
    condition:
        3 of ($pool, $wallet, $threads, $xmrig)
}

rule TPOT_Gafgyt_Mozi_ARM_UPX
{
    meta:
        description = "Gafgyt/Mozi IoT botnet ARM UPX-packed — highest confidence sample"
        author      = "Prince Lassey"
        date        = "2026-05-27"
        sha256      = "e15e93db3ce3a8a22adb4b18e0e37b93f39c495e4a97008f9b1a9a42e1fac2b0"
        mitre       = "T1498, T1496, T1027"
        severity    = "CRITICAL"
        vt_score    = "47/62 — 75.8%"
        community   = "-290 (most flagged in dataset)"
    strings:
        $upx     = "UPX!" ascii
        $gafgyt  = "Gafgyt" ascii nocase
        $mozi    = "Mozi" ascii nocase
        $busybox = "/bin/busybox" ascii
        $arm     = { 7F 45 4C 46 01 01 01 }  // ELF ARM LE header
    condition:
        $arm and $upx and any of ($gafgyt, $mozi, $busybox)
}

rule TPOT_PDF_Exploit_DLL_Injection
{
    meta:
        description = "PDF exploit payload with DLL injection and Adobe C2 blending"
        author      = "Prince Lassey"
        date        = "2026-05-27"
        sha256      = "a1b6223a3ecb37b9f7e4a52909a08d9fd8f8f80aee46466127ea0f078c7f5437"
        mitre       = "T1055, T1566.001, T1218.011, T1070.001"
        severity    = "HIGH"
        note        = "LOW DETECTION HIGH THREAT — beacons via acroipm.adobe.com"
    strings:
        $adobe_c2  = "acroipm.adobe.com" ascii
        $dll_name  = "jrDipYdVd.exe" ascii
        $evasion   = "wevtutil" ascii
        $acrobat   = "AcroRd32.exe" ascii
    condition:
        2 of ($adobe_c2, $dll_name, $evasion, $acrobat)
}


rule TPOT_Fresh_ARM_ELF_May2026{
    meta:
        description = "Fresh ARM ELF — first seen 4 days before honeypot capture May 2026"
        author      = "Prince Lassey"
        date        = "2026-05-30"
        sha256      = "697e4904339fc76cc9879b7fdcd1d67d96654b33beb06769d92a78c8fa87f028"
        mitre       = "T1497, T1071"
        severity    = "CRITICAL"
        note        = "C2 contacts 176.65.139.3"
        first_seen  = "2026-05-25"
    strings:
        $c2      = "176.65.139.3" ascii
        $arm_hdr = { 7F 45 4C 46 01 }  // ELF ARM header
        $dbg_chk = "detect-debug-environment" ascii nocase
        $cpu_chk = "checks-cpu-name" ascii nocase
    condition:
        $arm_hdr and ($c2 or $dbg_chk or $cpu_chk)
}