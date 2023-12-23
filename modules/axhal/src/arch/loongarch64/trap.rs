use super::context::TrapFrame;
use loongarch64::register::estat::{self, Exception, Trap};
use crate::arch::loongarch64::unaligned::emulate_load_store_insn;

core::arch::global_asm!(
    include_str!("trap.S"),
    trapframe_size = const core::mem::size_of::<TrapFrame>(),
);


fn handle_breakpoint(era: &mut usize) {
    debug!("Exception(Breakpoint) @ {:#x} ", era);
    *era += 4;
}

fn handle_unaligned(tf: &mut TrapFrame) {
    unsafe { emulate_load_store_insn(tf) }
}

#[no_mangle]
fn loongarch64_trap_handler(tf: &mut TrapFrame) {
    let estat = estat::read();
    match estat.cause() {
        Trap::Exception(Exception::Breakpoint) => handle_breakpoint(&mut tf.era),
        Trap::Exception(Exception::AddressNotAligned) => handle_unaligned(tf),
        Trap::Interrupt(_) => {
            let irq_num: usize = estat.is().trailing_zeros() as usize;
            crate::trap::handle_irq_extern(irq_num)
        }
        _ => {
            panic!(
                "Unhandled trap {:?} @ {:#x}:\n{:#x?}",
                estat.cause(),
                tf.era,
                tf
            );
        }
    }
}
