
use super::context::TrapFrame;
use core::arch::asm;

extern "C" {
    fn unaligned_read(addr: u64, value: &u64, n:u64, symbol: u32) -> i32;
    fn unaligned_write(addr: u64, value: u64, n:u64) -> i32;
}

core::arch::global_asm!(include_str!("unaligned.S"));


#[inline]
fn asm_write_fpr_0(val: u64) {
    unsafe { asm!("movgr2fr.d $f0,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_1(val: u64) {
    unsafe { asm!("movgr2fr.d $f1,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_2(val: u64) {
    unsafe { asm!("movgr2fr.d $f2,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_3(val: u64) {
    unsafe { asm!("movgr2fr.d $f3,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_4(val: u64) {
    unsafe { asm!("movgr2fr.d $f4,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_5(val: u64) {
    unsafe { asm!("movgr2fr.d $f5,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_6(val: u64) {
    unsafe { asm!("movgr2fr.d $f6,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_7(val: u64) {
    unsafe { asm!("movgr2fr.d $f7,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_8(val: u64) {
    unsafe { asm!("movgr2fr.d $f8,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_9(val: u64) {
    unsafe { asm!("movgr2fr.d $f9,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_10(val: u64) {
    unsafe { asm!("movgr2fr.d $f10,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_11(val: u64) {
    unsafe { asm!("movgr2fr.d $f11,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_12(val: u64) {
    unsafe { asm!("movgr2fr.d $f12,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_13(val: u64) {
    unsafe { asm!("movgr2fr.d $f13,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_14(val: u64) {
    unsafe { asm!("movgr2fr.d $f14,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_15(val: u64) {
    unsafe { asm!("movgr2fr.d $f15,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_16(val: u64) {
    unsafe { asm!("movgr2fr.d $f16,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_17(val: u64) {
    unsafe { asm!("movgr2fr.d $f17,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_18(val: u64) {
    unsafe { asm!("movgr2fr.d $f18,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_19(val: u64) {
    unsafe { asm!("movgr2fr.d $f19,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_20(val: u64) {
    unsafe { asm!("movgr2fr.d $f20,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_21(val: u64) {
    unsafe { asm!("movgr2fr.d $f21,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_22(val: u64) {
    unsafe { asm!("movgr2fr.d $f22,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_23(val: u64) {
    unsafe { asm!("movgr2fr.d $f23,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_24(val: u64) {
    unsafe { asm!("movgr2fr.d $f24,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_25(val: u64) {
    unsafe { asm!("movgr2fr.d $f25,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_26(val: u64) {
    unsafe { asm!("movgr2fr.d $f26,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_27(val: u64) {
    unsafe { asm!("movgr2fr.d $f27,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_28(val: u64) {
    unsafe { asm!("movgr2fr.d $f28,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_29(val: u64) {
    unsafe { asm!("movgr2fr.d $f29,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_30(val: u64) {
    unsafe { asm!("movgr2fr.d $f30,  {val} ", val = in(reg) val) }
}

#[inline]
fn asm_write_fpr_31(val: u64) {
    unsafe { asm!("movgr2fr.d $f31,  {val} ", val = in(reg) val) }
}




#[inline]
fn asm_read_fpr_0() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f0", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_1() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f1", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_2() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f2", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_3() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f3", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_4() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f4", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_5() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f5", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_6() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f6", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_7() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f7", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_8() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f8", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_9() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f9", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_10() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f10", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_11() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f11", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_12() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f12", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_13() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f13", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_14() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f14", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_15() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f15", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_16() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f16", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_17() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f17", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_18() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f18", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_19() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f19", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_20() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f20", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_21() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f21", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_22() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f22", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_23() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f23", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_24() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f24", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_25() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f25", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_26() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f26", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_27() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f27", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_28() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f28", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_29() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f29", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_30() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f30", val = out(reg) value)}
    value
}

#[inline]
fn asm_read_fpr_31() -> u64 {
    let mut value: u64;
    unsafe { asm!( "movfr2gr.d {val}, $f31", val = out(reg) value)}
    value
}


pub fn write_fpr(fd:usize,  val: u64) {
    match fd {
        0 => asm_write_fpr_0(val),
        1 => asm_write_fpr_1(val),
        2 => asm_write_fpr_2(val),
        3 => asm_write_fpr_3(val),
        4 => asm_write_fpr_4(val),
        5 => asm_write_fpr_5(val),
        6 => asm_write_fpr_6(val),
        7 => asm_write_fpr_7(val),
        8 => asm_write_fpr_8(val),
        9 => asm_write_fpr_9(val),
        10 => asm_write_fpr_10(val),
        11 => asm_write_fpr_11(val),
        12 => asm_write_fpr_12(val),
        13 => asm_write_fpr_13(val),
        14 => asm_write_fpr_14(val),
        15 => asm_write_fpr_15(val),
        16 => asm_write_fpr_16(val),
        17 => asm_write_fpr_17(val),
        18 => asm_write_fpr_18(val),
        19 => asm_write_fpr_19(val),
        20 => asm_write_fpr_20(val),
        21 => asm_write_fpr_21(val),
        22 => asm_write_fpr_22(val),
        23 => asm_write_fpr_23(val),
        24 => asm_write_fpr_24(val),
        25 => asm_write_fpr_25(val),
        26 => asm_write_fpr_26(val),
        27 => asm_write_fpr_27(val),
        28 => asm_write_fpr_28(val),
        29 => asm_write_fpr_29(val),
        30 => asm_write_fpr_30(val),
        31 => asm_write_fpr_31(val),
        _ => {panic!("Undefined Float Register")}
    }
}


pub fn read_fpr(fd:usize) -> u64 {
    let value: u64;
    match fd {
        0 => value = asm_read_fpr_0(),
        1 => value = asm_read_fpr_1(),
        2 => value = asm_read_fpr_2(),
        3 => value = asm_read_fpr_3(),
        4 => value = asm_read_fpr_4(),
        5 => value = asm_read_fpr_5(),
        6 => value = asm_read_fpr_6(),
        7 => value = asm_read_fpr_7(),
        8 => value = asm_read_fpr_8(),
        9 => value = asm_read_fpr_9(),
        10 => value = asm_read_fpr_10(),
        11 => value = asm_read_fpr_11(),
        12 => value = asm_read_fpr_12(),
        13 => value = asm_read_fpr_13(),
        14 => value = asm_read_fpr_14(),
        15 => value = asm_read_fpr_15(),
        16 => value = asm_read_fpr_16(),
        17 => value = asm_read_fpr_17(),
        18 => value = asm_read_fpr_18(),
        19 => value = asm_read_fpr_19(),
        20 => value = asm_read_fpr_20(),
        21 => value = asm_read_fpr_21(),
        22 => value = asm_read_fpr_22(),
        23 => value = asm_read_fpr_23(),
        24 => value = asm_read_fpr_24(),
        25 => value = asm_read_fpr_25(),
        26 => value = asm_read_fpr_26(),
        27 => value = asm_read_fpr_27(),
        28 => value = asm_read_fpr_28(),
        29 => value = asm_read_fpr_29(),
        30 => value = asm_read_fpr_30(),
        31 => value = asm_read_fpr_31(),
        _ => {panic!("Undefined Float Register")}
    }
        value
}


pub  const LDH_OP  :u32 = 0xa1;
pub  const LDHU_OP :u32 = 0xa9;
pub  const LDW_OP  :u32 = 0xa2;
pub  const LDWU_OP :u32 = 0xaa;
pub  const LDD_OP  :u32 = 0xa3;
pub  const STH_OP  :u32 = 0xa5;
pub  const STW_OP  :u32 = 0xa6;
pub  const STD_OP  :u32 = 0xa7;

pub  const LDPTRW_OP :u32 = 0x24;
pub  const LDPTRD_OP :u32 = 0x26;
pub  const STPTRW_OP :u32 = 0x25;
pub  const STPTRD_OP :u32 = 0x27;

pub  const LDXH_OP  :u32 = 0x7048;
pub  const LDXHU_OP :u32 = 0x7008;
pub  const LDXW_OP  :u32 = 0x7010;
pub  const LDXWU_OP :u32 = 0x7050;
pub  const LDXD_OP  :u32 = 0x7018;
pub  const STXH_OP  :u32 = 0x7028;
pub  const STXW_OP  :u32 = 0x7030;
pub  const STXD_OP  :u32 = 0x7038;

pub  const FLDS_OP :u32 = 0xac;
pub  const FLDD_OP :u32 = 0xae;
pub  const FSTS_OP :u32 = 0xad;
pub  const FSTD_OP :u32 = 0xaf;

pub  const FSTXS_OP :u32 = 0x7070;
pub  const FSTXD_OP :u32 = 0x7078;
pub  const FLDXS_OP :u32 = 0x7060;
pub  const FLDXD_OP :u32 = 0x7068;


pub unsafe fn emulate_load_store_insn (pt_regs: &mut  TrapFrame) {
    
    let la_inst: u32;
    let addr: u64;
    let rd: usize;

    let mut value: u64 = 0;
    let mut res: i32 = 0;

    debug!("Unaligned Access PC @ {:#x} ", pt_regs.era);

    unsafe {
        asm!(
            "ld.w {val}, {addr}, 0 ",
             addr = in(reg) pt_regs.era as u64,
             val = out(reg) la_inst,
        )
    }
    addr = pt_regs.badv as u64;
    rd = (la_inst & 0x1f) as usize;

    if  (la_inst >> 22 ) == LDD_OP
          ||  (la_inst >> 24 ) == LDPTRD_OP
          ||  (la_inst >> 15 ) == LDXD_OP  {
        res = unaligned_read(addr, &value, 8, 1);
        if res < 0 { panic!("Address Error @ {:#x}", addr) }
        pt_regs.regs[rd] = value as usize;
    } else if (la_inst >> 22 ) == LDW_OP
          ||  (la_inst >> 24 ) == LDPTRW_OP
          ||  (la_inst >> 15 ) == LDXW_OP  {
        res = unaligned_read(addr, &value, 4, 1);
        if res < 0 { panic!("Address Error @ {:#x}", addr) }
        pt_regs.regs[rd] = value as usize;
    } else if (la_inst >> 22 ) == LDWU_OP
          ||  (la_inst >> 15 ) == LDXWU_OP  {
        res = unaligned_read(addr, &value, 4, 0);
        if res < 0 { panic!("Address Error @ {:#x}", addr) }
        pt_regs.regs[rd] = value as usize;
    } else if (la_inst >> 22 ) == LDH_OP
          ||  (la_inst >> 15 ) == LDXH_OP  {
        res = unaligned_read(addr, &value, 2, 1);
        if res < 0 { panic!("Address Error @ {:#x}", addr) }
        pt_regs.regs[rd] = value as usize;
    } else if (la_inst >> 22 ) == LDHU_OP
          ||  (la_inst >> 15 ) == LDXHU_OP  {
        res = unaligned_read(addr, &value, 2, 0);
        if res < 0 { panic!("Address Error @ {:#x}", addr) }
        pt_regs.regs[rd] = value as usize;
    } else if (la_inst >> 22 ) == STD_OP
          ||  (la_inst >> 24 ) == STPTRD_OP
          ||  (la_inst >> 15 ) == STXD_OP {
        value = pt_regs.regs[rd] as u64;
        res = unaligned_write(addr, value, 8);
    } else if (la_inst >> 22 ) == STW_OP
          ||  (la_inst >> 24 ) == STPTRW_OP
          ||  (la_inst >> 15 ) == STXW_OP {
        value = pt_regs.regs[rd] as u64;
        res = unaligned_write(addr, value, 4);
    } else if (la_inst >> 22 ) == STH_OP
          ||  (la_inst >> 15 ) == STXH_OP {
        value = pt_regs.regs[rd] as u64;
        res = unaligned_write(addr, value, 2);
    } else if (la_inst >> 22 ) == FLDD_OP
          ||  (la_inst >> 15 ) == FLDXD_OP {
        res = unaligned_read(addr, &mut value, 8, 1);
        if res < 0 { panic!("Address Error @ {:#x}", addr) }
        write_fpr(rd, value);
    } else if (la_inst >> 22 ) == FLDS_OP
          ||  (la_inst >> 15 ) == FLDXS_OP {
        res = unaligned_read(addr, &mut value, 4, 1);
        if res < 0 { panic!("Address Error @ {:#x}", addr) }
        write_fpr(rd, value);
    } else if (la_inst >> 22 ) == FSTD_OP
          ||  (la_inst >> 15 ) == FSTXD_OP {
       value = read_fpr(rd);
        res = unaligned_write(addr, value, 8);
    } else if (la_inst >> 22 ) == FSTS_OP
          ||  (la_inst >> 15 ) == FSTXS_OP {
        value = read_fpr(rd);
        res = unaligned_write(addr, value, 4);
    }

    if res < 0 { panic!("Address Error @ {:#x}", addr) } 

    pt_regs.era += 4;
}



