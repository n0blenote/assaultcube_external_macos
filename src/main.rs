//! A script to read and dump to stdout the current register values of a
//! process.

extern crate libc;
extern crate mach2;

use std::io;
use std::mem;
use std::ptr;

use colored::Colorize;
use mach2::kern_return::KERN_SUCCESS;
use mach2::mach_types::{task_t, thread_act_array_t};
use mach2::message::mach_msg_type_number_t;
use mach2::port::mach_port_name_t;
use mach2::task::{task_resume, task_suspend, task_threads};
use mach2::thread_act::thread_get_state;
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::*;
use mach2::vm_prot::*;

pub const VM_REGION_BASIC_INFO_64: i32 = 9;
pub const VM_REGION_BASIC_INFO_COUNT_64: u32 = 10;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct vm_region_basic_info_64 {
    pub protection: u32,
    pub max_protection: u32,
    pub inheritance: u32,
    pub shared: u32,
    pub reserved: u32,
    pub offset: u64,
    pub behavior: u32,
    pub user_wired_count: u16,
}

type vm_region_info_t = *mut ::libc::c_int;
/* Copypasta from Mach2 */

#[cfg(target_arch = "aarch64")]
use mach2::thread_status::ARM_THREAD_STATE64 as THREAD_STATE64;
#[cfg(target_arch = "x86_64")]
use mach2::thread_status::x86_THREAD_STATE64 as THREAD_STATE64;

#[cfg(target_arch = "aarch64")]
use mach2::structs::arm_thread_state64_t as thread_state64_t;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use mach2::structs::x86_thread_state64_t as thread_state64_t;
use mach2::vm_types::mach_vm_address_t;
use mach2::vm_types::mach_vm_size_t;

use std::io::prelude::*;

#[cfg(target_arch = "aarch64")]
fn print_arm64_registers(state: &mach2::structs::arm_thread_state64_t) {
    println!("{}   = 0x{:016x}", "fp".green(), state.__fp);
    println!("{}   = 0x{:016x}", "lr".green(), state.__lr);
    println!("{}   = 0x{:016x}", "sp".green(), state.__sp);
    println!("{}   = 0x{:016x}", "pc".green(), state.__pc);
    println!("{} = 0x{:08x}", "cpsr".green(), state.__cpsr);
    // Print general-purpose registers x0 - x28
    for (i, reg) in state.__x.iter().enumerate() {
        println!("x{: <2} = 0x{:016x}", i, reg);
    }

    println!("{} = {}", "flags".yellow().underline(), state.__flags); // Custom/debug info
}

fn read_int() -> Result<::libc::c_int, ()> {
    let stdin = io::stdin();
    let mut line = String::new();

    stdin.read_line(&mut line).ok().unwrap();
    let mut value: ::libc::c_int = 0;

    for c in line.chars().take_while(|&c| c != '\n') {
        if let Some(d) = c.to_digit(10) {
            value = value * 10 + (d as ::libc::c_int);
        } else {
            return Err(());
        }
    }
    return Ok(value);
}

fn resume(task: task_t) {
    unsafe {
        let kret = task_resume(task);
        if kret != KERN_SUCCESS {
            println!(
                "{}, kern_return_t error {}",
                "Did not succeed in resuming task.".red(),
                kret
            );
            panic!();
        }
    }
}

unsafe fn get_base_address(task: task_t) -> Option<u64> {
    let mut address: mach_vm_address_t = 1; // skip null page
    let mut size: mach_vm_size_t = 0;
    let mut info = vm_region_basic_info_64::default();
    let mut count = VM_REGION_BASIC_INFO_COUNT_64;
    let mut object_name: mach_port_name_t = 0;

    unsafe {
        while mach_vm_region(
            //regions (_info/64/_recurse)
            task,
            &mut address,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            &mut info as *mut _ as vm_region_info_t,
            &mut count,
            &mut object_name,
        ) == KERN_SUCCESS
        // run till kernel yells at us
        {
            // look for read + exec regions that might contain Mach-O header
            let prot: i32 = info.protection.try_into().unwrap();
            if (prot & VM_PROT_READ != 0) && (prot & VM_PROT_EXECUTE != 0) {
                println!(
                    "{}: 0x{:x} - 0x{:x}",
                    "Found executable region".green(),
                    address,
                    address + size
                );
                return Some(address);
            }
            address += size; // push ahead from previous chunk given from mach_vm_region
        }
    }

    None
}

fn main() {
    print!("Enter pid: ");
    io::stdout().flush().ok();

    let pid: i32 = match read_int() {
        Ok(v) => v,
        Err(_) => {
            println!("{}", "Bad PID - please make sure you check!!".red());
            return;
        }
    };

    println!("pid = {}", &pid);

    let task: mach_port_name_t = 0;
    unsafe {
        let kret = task_for_pid(
            mach_task_self() as mach_port_name_t,
            pid,
            mem::transmute(&task),
        );
        if kret != KERN_SUCCESS {
            println!(
                "{} {}, kern_return_t message: {}",
                "Did not succeed in getting task for pid".red(),
                pid.to_string().red(),
                kret.to_string().red()
            );
            println!(
                "{}",
                "Did you forget to run with 'sudo'? This script will probably fail without it!"
                    .yellow()
                    .italic()
            );
            return;
        }
    }

    println!("{} = 0x{:x}", "Got Mach task".green().bold(), &task);

    unsafe {
        let kret = task_suspend(task as task_t);
        if kret != KERN_SUCCESS {
            println!(
                "{} kern_return_t error {}",
                "Did not succeed in suspending task.".red(),
                kret
            );
            return;
        }
    }

    let thread_list: thread_act_array_t = ptr::null_mut();
    let thread_count: mach_msg_type_number_t = 0;
    unsafe {
        let kret = task_threads(
            task as task_t,
            mem::transmute(&thread_list),
            mem::transmute(&thread_count),
        );
        if kret != KERN_SUCCESS {
            println!(
                "Did not succeed in getting task's threads kern_return_t error {}",
                kret
            );
            resume(task as task_t);
            return;
        }
    }

    // Get base address
    unsafe {
        get_base_address(task);
    }

    println!("Task is running {} threads", &thread_count);

    unsafe {
        let threads = std::slice::from_raw_parts(thread_list, thread_count as usize);
        let state = thread_state64_t::new();
        let state_count = thread_state64_t::count();
        for (idx, &thread) in threads.iter().enumerate() {
            println!(
                "{} {}",
                "Thread ".purple().underline(),
                idx.to_string().purple().underline()
            );
            let kret = thread_get_state(
                // check if thread is still OK (kern_return_t) to use by Mach or we are in
                // TROUBLE!!!
                thread,
                THREAD_STATE64,
                mem::transmute(&state), // natural_t *thread_state_t
                mem::transmute(&state_count),
            );
            if kret != KERN_SUCCESS {
                println!("Did not succeed in getting task's thread state");
                println!("kern_return_t error {}", kret);
                continue;
            }

            print_arm64_registers(&state);
        }

        mach_vm_deallocate(
            mach_task_self(),
            thread_list as _,
            ((thread_count as usize) * mem::size_of::<libc::c_int>()) as _,
        );
    }
    // Resume task and relinquish memory for the mach task
    resume(task as task_t);
}
