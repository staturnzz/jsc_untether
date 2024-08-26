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
    if len(sys.argv) != 2:
        print("python bin_to_js.py <bin>")
        return

    file_path = sys.argv[1]    
    if os.path.exists("shellcode.js"):
        os.remove("shellcode.js")    
    process_bin_file(file_path)

    with open("shellcode.js", 'a') as target:
        target.write("jitted_func();")


if __name__ == "__main__":
    main()
