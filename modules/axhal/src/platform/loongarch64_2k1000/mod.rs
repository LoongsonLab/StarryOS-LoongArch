mod boot;
pub mod console;
pub mod mem;
pub mod misc;
pub mod time;

#[cfg(feature = "irq")]
pub mod irq;

#[cfg(feature = "smp")]
pub mod mp;

extern "C" {
    fn trap_vector_base();
    fn handle_tlb_refill();
    fn rust_main(cpu_id: usize, dtb: usize);
    fn _sbss();
    fn _ebss();
    #[cfg(feature = "smp")]
    fn rust_main_secondary(cpu_id: usize);
}

#[no_mangle]
unsafe extern "C" fn rust_entry(cpu_id: usize, _dtb: usize) {
    crate::mem::clear_bss();
    crate::cpu::init_primary(cpu_id);
    crate::arch::set_trap_vector_base(trap_vector_base as usize);
    crate::arch::tlb_init(boot::KERNEL_PAGE_TABLE.as_ptr() as usize, handle_tlb_refill as usize);
    rust_main(cpu_id, 0);
}

#[cfg(feature = "smp")]
unsafe extern "C" fn rust_entry_secondary(cpu_id: usize) {
    crate::arch::set_trap_vector_base(trap_vector_base as usize);
    crate::arch::tlb_init(boot::KERNEL_PAGE_TABLE.as_ptr() as usize, handle_tlb_refill as usize);
    crate::cpu::init_secondary(cpu_id);
    rust_main_secondary(cpu_id);
}

/// Initializes the platform devices for the primary CPU.
///
/// For example, the interrupt controller and external interrupts.
pub fn platform_init() {
    #[cfg(feature = "irq")]
    self::irq::init_percpu();
    self::time::init_percpu();
}

/// Initializes the platform devices for secondary CPUs.
#[cfg(feature = "smp")]
pub fn platform_init_secondary() {
    #[cfg(feature = "irq")]
    self::irq::init_percpu();
    self::time::init_percpu();
}
