//! Reads the text of one PDF for the gateway, which trusts neither the file nor this process.
//!
//! The file arrives on standard input. Each page leaves on standard output as its length in
//! four little-endian bytes and then its UTF-8 text. The exit status says how reading ended.
//!
//! Before it reads a byte of the file, the process limits its own memory and processor time,
//! and then gives up every system call that reading does not need. A file that takes over the
//! parser can compute, read its input and write to its output, and nothing else.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};

use pdf_oxide::PdfDocument;

const UNREADABLE: i32 = 1;
const TOO_MANY_PAGES: i32 = 2;
const TOO_MUCH_TEXT: i32 = 3;
const NEEDS_PASSWORD: i32 = 4;
const OUT_OF_MEMORY: i32 = 5;
const NOT_CONFINED: i32 = 6;

/// Ends the process when memory runs out, so that the gateway can tell that from a broken file.
struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        or_exit(System.alloc(layout))
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        or_exit(System.alloc_zeroed(layout))
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        or_exit(System.realloc(pointer, layout, size))
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn or_exit(pointer: *mut u8) -> *mut u8 {
    if pointer.is_null() {
        exit(OUT_OF_MEMORY);
    }
    pointer
}

/// Ends the process without the runtime's cleanup, which makes system calls that are given up.
fn exit(status: i32) -> ! {
    unsafe { libc::_exit(status) }
}

fn main() {
    let limits: Vec<u64> = std::env::args().skip(1).filter_map(|value| value.parse().ok()).collect();
    let [max_pages, max_text, max_memory, max_seconds] = limits[..] else {
        eprintln!("usage: stogas-pdftext <pages> <text bytes> <memory bytes> <processor seconds>");
        exit(NOT_CONFINED);
    };
    if !limit(libc::RLIMIT_AS, max_memory) || !limit(libc::RLIMIT_CPU, max_seconds) || !limit(libc::RLIMIT_CORE, 0) {
        exit(NOT_CONFINED);
    }
    if !confine() {
        exit(NOT_CONFINED);
    }
    let mut file = Vec::new();
    if std::io::stdin().lock().read_to_end(&mut file).is_err() {
        exit(UNREADABLE);
    }
    exit(match read(file, max_pages as usize, max_text as usize) {
        Ok(()) => 0,
        Err(status) => status,
    });
}

fn limit(resource: libc::__rlimit_resource_t, value: u64) -> bool {
    let limit = libc::rlimit { rlim_cur: value, rlim_max: value };
    unsafe { libc::setrlimit(resource, &limit) == 0 }
}

fn read(file: Vec<u8>, max_pages: usize, max_text: usize) -> Result<(), i32> {
    let document = PdfDocument::from_bytes(file).map_err(|_| UNREADABLE)?;
    if !document.is_authenticated() {
        return Err(NEEDS_PASSWORD);
    }
    let pages = document.page_count().map_err(|_| UNREADABLE)?;
    if pages > max_pages {
        return Err(TOO_MANY_PAGES);
    }
    let mut out = std::io::stdout().lock();
    let mut written = 0;
    for page in 0..pages {
        let text = document.extract_text(page).map_err(|_| UNREADABLE)?;
        written += text.len();
        if written > max_text {
            return Err(TOO_MUCH_TEXT);
        }
        out.write_all(&(text.len() as u32).to_le_bytes())
            .and_then(|_| out.write_all(text.as_bytes()))
            .map_err(|_| UNREADABLE)?;
    }
    out.flush().map_err(|_| UNREADABLE)
}

/// The system calls that reading needs: input, output, memory, random seeds for hash maps, and
/// exit.
const ALLOWED: [libc::c_long; 11] = [
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_brk,
    libc::SYS_madvise,
    libc::SYS_getrandom,
    libc::SYS_rt_sigreturn,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

#[cfg(target_arch = "x86_64")]
const ARCHITECTURE: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const ARCHITECTURE: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

// Classic BPF: load a 32-bit word of the call's description, compare it, return a verdict.
const LOAD: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JUMP_IF_EQUAL: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const RETURN: u16 = 0x06; // BPF_RET | BPF_K
const NUMBER_OFFSET: u32 = 0; // seccomp_data.nr
const ARCHITECTURE_OFFSET: u32 = 4; // seccomp_data.arch
const ALLOW: u32 = 0x7fff_0000; // SECCOMP_RET_ALLOW
const KILL: u32 = 0x8000_0000; // SECCOMP_RET_KILL_PROCESS
const REFUSE: u32 = 0x0005_0000 | libc::ENOSYS as u32; // SECCOMP_RET_ERRNO

/// Gives up every system call that is not in ALLOWED, for good: the kernel refuses the others
/// with ENOSYS, so the parser sees a failed call where it probes for something optional, and
/// the filter cannot be removed. Returns false where the kernel has no such filter.
fn confine() -> bool {
    let instruction = |code, jump_if_true, k| libc::sock_filter { code, jt: jump_if_true, jf: 0, k };
    let mut filter = vec![
        instruction(LOAD, 0, ARCHITECTURE_OFFSET),
        instruction(JUMP_IF_EQUAL, 1, ARCHITECTURE),
        instruction(RETURN, 0, KILL),
        instruction(LOAD, 0, NUMBER_OFFSET),
    ];
    for (index, call) in ALLOWED.iter().enumerate() {
        // An allowed call jumps over the remaining comparisons and the refusal.
        filter.push(instruction(JUMP_IF_EQUAL, (ALLOWED.len() - index) as u8, *call as u32));
    }
    filter.push(instruction(RETURN, 0, REFUSE));
    filter.push(instruction(RETURN, 0, ALLOW));
    let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program as *const libc::sock_fprog) == 0
    }
}
