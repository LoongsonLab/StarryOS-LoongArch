.altmacro
.macro COPY n
    ld.d $t2, $a0, (\n)*8
    st.d $t2, $a1, (\n)*8
.endm
    .section .text
    .globl __copy
__copy:
    # __copy(
    #     frame_address: *const TrapFrame,
    #     kernel_base: *mut T
    # )
    .set n, 0
    .rept 38
        COPY %n
        .set n, n + 1
    .endr
    ret

