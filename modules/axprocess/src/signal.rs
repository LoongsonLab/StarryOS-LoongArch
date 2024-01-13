//! 负责处理进程中与信号相关的内容
extern crate alloc;
use alloc::sync::Arc;
use axerrno::{AxError, AxResult};
use axhal::{arch::TrapFrame, cpu::this_cpu_id, KERNEL_PROCESS_ID};
use axlog::{info, warn, trace};
use axsignal::{
    action::{SigActionFlags, SignalDefault, SIG_IGN},
    info::SigInfo,
    signal_no::SignalNo,
    ucontext::SignalUserContext,
    SignalHandler, SignalSet,
};
use axsync::Mutex;
use axtask::{SignalCaller, TaskState, RUN_QUEUE};

pub struct SignalModule {
    pub sig_info: bool,
    pub last_trap_frame_for_signal: Option<TrapFrame>,
    pub signal_handler: Arc<Mutex<SignalHandler>>,
    pub signal_set: SignalSet,
}

impl SignalModule {
    pub fn init_signal(signal_handler: Option<Arc<Mutex<SignalHandler>>>) -> Self {
        let signal_handler = if signal_handler.is_none() {
            Arc::new(Mutex::new(SignalHandler::new()))
        } else {
            signal_handler.unwrap()
        };
        let signal_set = SignalSet::new();
        let last_trap_frame_for_signal = None;
        let sig_info = false;
        Self {
            sig_info,
            last_trap_frame_for_signal,
            signal_handler,
            signal_set,
        }
    }
}

const USER_SIGNAL_PROTECT: usize = 512;

use crate::{
    current_process, current_task, exit_current_task,
    process::{PID2PC, TID2TASK},
};

/// 将保存的trap上下文填入内核栈中
///
/// 若使用了SIG_INFO，此时会对原有trap上下文作一定修改。
///
/// 若确实存在可以被恢复的trap上下文，则返回true
#[no_mangle]
pub fn load_trap_for_signal() -> bool {
    let current_process = current_process();
    let current_task = current_task();
    // let signal_module = inner
    //     .signal_module
    //     .iter_mut()
    //     .find(|(id, _)| *id == current_task.id().as_u64())
    //     .map(|(_, handler)| handler)
    //     .unwrap();
    let mut signal_modules = current_process.signal_modules.lock();
    let signal_module = signal_modules.get_mut(&current_task.id().as_u64()).unwrap();
    if let Some(old_trap_frame) = signal_module.last_trap_frame_for_signal.take() {
        unsafe {
            let now_trap_frame = current_task.get_first_trap_frame();
            // 考虑当时调用信号处理函数时，sp对应的地址上的内容即是SignalUserContext
            // 此时认为一定通过sig_return调用这个函数
            // 所以此时sp的位置应该是SignalUserContext的位置
            let sp = (*now_trap_frame).regs[3];
            *now_trap_frame = old_trap_frame;
            // 若存在SIG_INFO，此时pc可能发生变化
            if signal_module.sig_info {
                let pc = (*(sp as *const SignalUserContext)).get_pc();
                (*now_trap_frame).era = pc;
            }
        }
        true
    } else {
        false
    }
}

/// 处理 Terminate 类型的信号
fn terminate_process(signal: SignalNo) {
    let current_task = current_task();
    warn!("Terminate process: {}", current_task.get_process_id());
    if current_task.is_leader() {
        exit_current_task(signal as i32);
    } else {
        // 此时应当关闭当前进程
        // 选择向主线程发送信号内部来关闭
        send_signal_to_process(current_task.get_process_id() as isize, signal as isize).unwrap();
        exit_current_task(-1);
    }
}

pub fn dbg_test() {

}

/// 处理当前进程的信号
///
/// 若返回值为真，代表需要进入处理信号，因此需要执行trap的返回
pub fn handle_signals() {
    let process = current_process();
    let current_task = current_task();
    if process.get_zombie() {
        if current_task.is_leader() {
            return;
        }
        // 进程退出了，在测试环境下非主线程应该立即退出
        exit_current_task(0);
    }

    if process.pid() == KERNEL_PROCESS_ID {
        // 内核进程不处理信号
        return;
    }
    let mut signal_modules = process.signal_modules.lock();

    let signal_module = signal_modules.get_mut(&current_task.id().as_u64()).unwrap();
    let signal_set = &mut signal_module.signal_set;
    let sig_num = if let Some(sig_num) = signal_set.get_one_signal() {
        sig_num
    } else {
        return;
    };
    trace!(
        "cpu: {}, task: {}, handler signal: {}",
        this_cpu_id(),
        current_task.id().as_u64(),
        sig_num
    );
    let signal = SignalNo::from(sig_num);
    let mask = signal_set.mask;
    // 存在未被处理的信号
    if signal_module.last_trap_frame_for_signal.is_some() {
        // 之前的trap frame还未被处理
        // 说明之前的信号处理函数还未返回，即出现了信号嵌套。
        if signal == SignalNo::SIGSEGV || signal == SignalNo::SIGBUS {
            // 在处理信号的过程中又触发 SIGSEGV 或 SIGBUS，此时会导致死循环，所以直接结束当前进程
            drop(signal_modules);
            exit_current_task(-1);
        } else {
            return;
        }
    }
    // 之前的trap frame已经被处理
    // 说明之前的信号处理函数已经返回，即没有信号嵌套。
    // 此时可以将当前的trap frame保存起来
    signal_module.last_trap_frame_for_signal =
        Some((unsafe { *current_task.get_first_trap_frame() }).clone());
    // current_task.set_siginfo(false);
    signal_module.sig_info = false;
    // 调取处理函数
    let signal_handler = signal_module.signal_handler.lock();
    let action = signal_handler.get_action(sig_num);
    if action.is_none() {
        drop(signal_handler);
        drop(signal_modules);
        drop(current_task);
        // 未显式指定处理函数，使用默认处理函数
        match SignalDefault::get_action(signal) {
            SignalDefault::Ignore => {
                // 忽略，此时相当于已经完成了处理，所以要把trap上下文清空
                load_trap_for_signal();
            }
            SignalDefault::Terminate => {
                terminate_process(signal);
            }
            SignalDefault::Stop => {
                unimplemented!();
            }
            SignalDefault::Cont => {
                unimplemented!();
            }
            SignalDefault::Core => {
                terminate_process(signal);
            }
        }
        return;
    }
    let action = action.unwrap();
    if action.sa_handler == SIG_IGN {
        // 忽略处理
        return;
    }
    // 此时需要调用信号处理函数，注意调用的方式是：
    // 通过修改trap上下文的pc指针，使得trap返回之后，直接到达信号处理函数
    // 因此需要处理一系列的trap上下文，使得正确传参与返回。
    // 具体来说需要考虑两个方面：
    // 1. 传参
    // 2. 返回值ra地址的设定，与是否设置了SA_RESTORER有关

    // 注意是直接修改内核栈上的内容
    let trap_frame = unsafe { &mut *(current_task.get_first_trap_frame()) };

    // 新的trap上下文的sp指针位置，由于SIGINFO会存放内容，所以需要开个保护区域
    let mut sp = trap_frame.regs[3] - USER_SIGNAL_PROTECT;
    info!(
        "restorer :0x{:x}, handler: 0x{:x}",
        action.get_storer(),
        action.sa_handler
    );

    let old_pc = trap_frame.era;
    trap_frame.regs[1] = action.get_storer();
    trap_frame.era = action.sa_handler;
    // 传参
    trap_frame.regs[4] = sig_num;
    // 若带有SIG_INFO参数，则函数原型为fn(sig: SignalNo, info: &SigInfo, ucontext: &mut UContext)
    if action.sa_flags.contains(SigActionFlags::SA_SIGINFO) {
        // current_task.set_siginfo(true);
        signal_module.sig_info = true;
        // 注意16字节对齐
        sp = (sp - core::mem::size_of::<SigInfo>()) & !0xf;
        let mut info = SigInfo::default();
        info.si_signo = sig_num as i32;
        unsafe {
            *(sp as *mut SigInfo) = info;
        }
        trap_frame.regs[5] = sp;

        // 接下来存储ucontext
        sp = (sp - core::mem::size_of::<SignalUserContext>()) & !0xf;

        let ucontext = SignalUserContext::init(old_pc, mask);
        unsafe {
            *(sp as *mut SignalUserContext) = ucontext;
        }
        trap_frame.regs[6] = sp;
    }
    trap_frame.regs[3] = sp;
    info!("Trap_frame: 0x{:x}", trap_frame.regs[3]);
    drop(signal_handler);
    drop(signal_modules);
    dbg_test();
}

/// 从信号处理函数返回
///
/// 返回的值与原先syscall应当返回的值相同，即返回原先保存的trap上下文的a0的值
pub fn signal_return() -> isize {
    if load_trap_for_signal() {
        // 说明确实存在着信号处理函数的trap上下文
        // 此时内核栈上存储的是调用信号处理前的trap上下文
        let trap_frame = current_task().get_first_trap_frame();
        unsafe { (*trap_frame).regs[4] as isize }
    } else {
        // 没有进行信号处理，但是调用了sig_return
        // 此时直接返回-1
        -1
    }
}

/// 发送信号到指定的进程
///
/// 默认发送到该进程下的主线程
pub fn send_signal_to_process(pid: isize, signum: isize) -> AxResult<()> {
    let mut pid2pc = PID2PC.lock();
    if pid2pc.contains_key(&(pid as u64)) == false {
        return Err(axerrno::AxError::NotFound);
    }
    let process = pid2pc.get_mut(&(pid as u64)).unwrap();
    let mut now_id: Option<u64> = None;
    for task in process.tasks.lock().iter_mut() {
        if task.is_leader() {
            now_id = Some(task.id().as_u64());
            break;
        }
    }
    if now_id.is_some() {
        let mut signal_modules = process.signal_modules.lock();
        let signal_module = signal_modules.get_mut(&now_id.unwrap()).unwrap();
        signal_module.signal_set.try_add_signal(signum as usize);
        let tid2task = TID2TASK.lock();
        let main_task = Arc::clone(&tid2task.get(&now_id.unwrap()).unwrap());
        // 如果这个时候对应的线程是处于休眠状态的，则唤醒之，进入信号处理阶段
        if main_task.state() == TaskState::Blocked {
            RUN_QUEUE.lock().unblock_task(main_task, false);
        }
    }
    Ok(())
}

/// 发送信号到指定的线程
pub fn send_signal_to_thread(tid: isize, signum: isize) -> AxResult<()> {
    let tid2task = TID2TASK.lock();
    let task = if let Some(task) = tid2task.get(&(tid as u64)) {
        Arc::clone(task)
    } else {
        return Err(AxError::NotFound);
    };
    drop(tid2task);
    let pid = task.get_process_id();
    let pid2pc = PID2PC.lock();
    let process = if let Some(process) = pid2pc.get(&pid) {
        Arc::clone(process)
    } else {
        return Err(AxError::NotFound);
    };
    drop(pid2pc);
    let mut signal_modules = process.signal_modules.lock();
    if signal_modules.contains_key(&(tid as u64)) == false {
        return Err(axerrno::AxError::NotFound);
    }
    let signal_module = signal_modules.get_mut(&(tid as u64)).unwrap();
    signal_module.signal_set.try_add_signal(signum as usize);
    // 如果这个时候对应的线程是处于休眠状态的，则唤醒之，进入信号处理阶段
    if task.state() == TaskState::Blocked {
        RUN_QUEUE.lock().unblock_task(task, false);
    }
    Ok(())
}

struct SignalCallerImpl;
#[crate_interface::impl_interface]
impl SignalCaller for SignalCallerImpl {
    fn send_signal(tid: isize, signum: isize) {
        send_signal_to_thread(tid, signum).unwrap();
    }
}
