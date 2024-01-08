.macro SAVE_REGS
    st.d $ra, $sp, 8
    st.d $tp, $sp, 16

    csrrd $t0, 0x32
    st.d $t0, $sp, 96

    st.d $a0, $sp, 32
    st.d $a1, $sp, 40
    st.d $a2, $sp, 48
    st.d $a3, $sp, 56
    st.d $a4, $sp, 64
    st.d $a5, $sp, 72
    st.d $a6, $sp, 80
    st.d $a7, $sp, 88
    st.d $t1, $sp, 104
    st.d $t2, $sp, 112
    st.d $t3, $sp, 120
    st.d $t4, $sp, 128
    st.d $t5, $sp, 136
    st.d $t6, $sp, 144
    st.d $t7, $sp, 152
    st.d $t8, $sp, 160
    st.d $r21, $sp,168
    st.d $fp, $sp, 176
    st.d $s0, $sp, 184
    st.d $s1, $sp, 192
    st.d $s2, $sp, 200
    st.d $s3, $sp, 208
    st.d $s4, $sp, 216
    st.d $s5, $sp, 224
    st.d $s6, $sp, 232
    st.d $s7, $sp, 240
    st.d $s8, $sp, 248
.endm

.macro RESTORE_REGS
    ld.d $ra, $sp, 8
    ld.d $tp, $sp, 16
    ld.d $a0, $sp, 32
    ld.d $a1, $sp, 40
    ld.d $a2, $sp, 48
    ld.d $a3, $sp, 56
    ld.d $a4, $sp, 64
    ld.d $a5, $sp, 72
    ld.d $a6, $sp, 80
    ld.d $a7, $sp, 88
    ld.d $t0, $sp, 96
    ld.d $t1, $sp, 104
    ld.d $t2, $sp, 112
    ld.d $t3, $sp, 120
    ld.d $t4, $sp, 128
    ld.d $t5, $sp, 136
    ld.d $t6, $sp, 144
    ld.d $t7, $sp, 152
    ld.d $t8, $sp, 160
    ld.d $r21, $sp,168
    ld.d $fp, $sp, 176
    ld.d $s0, $sp, 184
    ld.d $s1, $sp, 192
    ld.d $s2, $sp, 200
    ld.d $s3, $sp, 208
    ld.d $s4, $sp, 216
    ld.d $s5, $sp, 224
    ld.d $s6, $sp, 232
    ld.d $s7, $sp, 240
    ld.d $s8, $sp, 248
.endm


.section .text
.balign 4096
.global trap_vector_base
trap_vector_base:
    csrwr       $t0, 0x32
    csrrd       $t0, 0x1
    andi        $t0, $t0, 0x3
    bnez        $t0, .Lfrom_userspace 

.Lfrom_kernel:
    move        $t0, $sp  
    addi.d      $sp, $sp, -{trapframe_size} // allocate space
    // save kernel sp
    st.d        $t0, $sp, 24
    b .Lcommon // $t0 save info

.Lfrom_userspace:       
    csrwr       $sp, 0x33                   // save user sp into SAVE1 CSR
    csrrd       $sp, 0x30                   // restore kernel sp
    addi.d      $sp, $sp, -{trapframe_size} // allocate space
    // save user sp
    csrrd       $t0, 0x33
    st.d        $t0, $sp, 24
     
.Lcommon:
    // save the registers.
    SAVE_REGS

    csrrd		$t2, 0x1
    st.d		$t2, $sp, 8*32  // prmd
    csrrd       $t1, 0x6        
    st.d        $t1, $sp, 8*33  // era
    csrrd       $t1, 0x7   
    st.d        $t1, $sp, 8*34  // badv  
    csrrd       $t1, 0x0   
    st.d        $t1, $sp, 8*35  // crmd    

    move $a0, $sp
    csrrd       $t0, 0x1
    andi        $a1, $t0, 0x3   // if user or kernel
    bl loongarch64_trap_handler

    // restore the registers.
    ld.d  $t1, $sp, 8*33  // era
    csrwr $t1, 0x6
    ld.d  $t2, $sp, 8*32  // prmd
    csrwr $t2, 0x1

    RESTORE_REGS

    // restore sp
    ld.d $sp, $sp, 24
    ertn


#define LOONGARCH_CSR_TLBRENTRY     0x88    /* TLB refill exception entry */
#define LOONGARCH_CSR_TLBRBADV      0x89    /* TLB refill badvaddr */
#define LOONGARCH_CSR_TLBRERA       0x8a    /* TLB refill ERA */
#define LOONGARCH_CSR_TLBRSAVE      0x8b    /* KScratch for TLB refill exception */
#define LOONGARCH_CSR_TLBRELO0      0x8c    /* TLB refill entrylo0 */
#define LOONGARCH_CSR_TLBRELO1      0x8d    /* TLB refill entrylo1 */
#define LOONGARCH_CSR_TLBREHI       0x8e    /* TLB refill entryhi */

#define LOONGARCH_CSR_PGDL          0x19    /* Page table base address when VA[47] = 0 */
#define LOONGARCH_CSR_PGDH          0x1a    /* Page table base address when VA[47] = 1 */
#define LOONGARCH_CSR_PGD           0x1b    /* Page table base */

.section .text
.balign 4096
.global handle_tlb_refill
handle_tlb_refill:
    csrwr   $t0, 0x8b
    csrrd   $t0, 0x1b
    lddir   $t0, $t0, 3
    lddir   $t0, $t0, 1
    ldpte   $t0, 0
    ldpte   $t0, 1
    tlbfill
    csrrd   $t0, 0x8b
    ertn
