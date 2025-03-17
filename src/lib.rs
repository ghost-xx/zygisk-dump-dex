#![feature(naked_functions)]
use dobby_rs::Address;
use jni::JNIEnv;
use log::{error, info, trace, warn};
use nix::{fcntl::OFlag, sys::stat::Mode};
use sha2::{Sha256, Digest};
use crossbeam_channel::{bounded, Sender};
use goblin::elf::{Elf, sym::STT_FUNC};
use std::{
    sync::{Mutex, Arc},
    fs::{File, create_dir_all},
    os::fd::{AsRawFd, FromRawFd},
    thread,
    mem,
};
use zygisk_rs::{register_zygisk_module, Api, AppSpecializeArgs, Module, ServerSpecializeArgs};
 
// --- 全局状态 --- 
lazy_static::lazy_static! {
    static ref CACHE: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    static ref WRITER_CHANNEL: (Sender<(String, Vec<u8>)>, thread::JoinHandle<()>) = {
        let (sender, receiver) = bounded(100);
        let handle = thread::spawn(move || {
            while let Ok((package, data)) = receiver.recv() {
                process_dex(&package, &data);
            }
        });
        (sender, handle)
    };
}
static mut OLD_OPEN_COMMON: usize = 0;
 
// --- 主模块定义 --- 
struct DexDumper {
    api: Api,
    env: JNIEnv<'static>,
}
 
impl Module for DexDumper {
    // 初始化与生命周期方法 
    fn new(api: Api, env: *mut jni_sys::JNIEnv) -> Self {
        android_logger::init_once(android_logger::Config::default().with_tag("DexDumper"));
        let env = unsafe { JNIEnv::from_raw(env.cast()).unwrap() };
        Self { api, env }
    }
 
    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        if let Err(e) = self.setup_hook() {
            error!("Hook setup failed: {}", e);
            self.api.set_option(zygisk_rs::ModuleOption::DlcloseModuleLibrary);
        }
    }
 
    fn post_app_specialize(&mut self, _: &AppSpecializeArgs) {
        unsafe {
            if OLD_OPEN_COMMON != 0 {
                dobby_rs::unhook(OLD_OPEN_COMMON);
            }
            libc::dlclose(self.api.module_handle());
        }
    }
}
 
// --- 核心逻辑实现 --- 
impl DexDumper {
    fn setup_hook(&self) -> anyhow::Result<()> {
        // 包名过滤 
        let package = self.get_package_name(args)?;
        if !check_allowlist(&package)? { return Ok(()); }
 
        // 动态符号解析 
        let open_common_addr = find_open_common()?;
        
        // PLT Hook 
        unsafe {
            OLD_OPEN_COMMON = dobby_rs::hook(open_common_addr, plt_hook_wrapper as Address)? as usize;
        }
        Ok(())
    }
 
    fn get_package_name(&self, args: &AppSpecializeArgs) -> anyhow::Result<String> {
        // 解析JNI获取包名（略）
    }
}
 
// --- Hook与数据处理 --- 
#[naked]
extern "C" fn plt_hook_wrapper() {
    unsafe { /* 汇编代码保存寄存器并调用new_open_common */ }
}
 
extern "C" fn new_open_common(base: *const u8, size: usize) {
    let dex_data = unsafe { std::slice::from_raw_parts(base, size) };
    let package = get_current_package().unwrap_or_default();
    
    // 内存校验 
    let original_hash = sha256(dex_data);
    let current_hash = sha256(unsafe { std::slice::from_raw_parts(base, size) });
    if original_hash != current_hash {
        warn!("Memory tampered: {}", package);
        return;
    }
 
    // 异步写入 
    WRITER_CHANNEL.0.send((package, dex_data.to_vec())).unwrap();
}
 
fn process_dex(package: &str, data: &[u8]) {
    // 去重校验 
    let hash = sha256(data);
    if CACHE.lock().unwrap().contains(&hash) { return; }
 
    // 文件写入 
    let dir = format!("/data/data/{}/dexes", package);
    if let Err(e) = create_dir_all(&dir) { 
        error!("Dir creation failed: {}", e);
        return;
    }
 
    let path = format!("{}/{}.dex", dir, hash);
    if let Err(e) = std::fs::write(&path, data) {
        error!("Write failed: {}", e);
    } else {
        CACHE.lock().unwrap().insert(hash);
    }
}
 
// --- 辅助工具函数 --- 
fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
 
fn find_open_common() -> anyhow::Result<Address> {
    // 动态解析ELF定位目标函数 
    let lib = unsafe { libloading::Library::new("libdexfile.so")? };
    let base = lib.as_ptr() as usize;
    
    let elf_data = unsafe { 
        std::slice::from_raw_parts(base as *const u8, 0x100000) // 模拟ELF读取 
    };
    let elf = Elf::parse(elf_data)?;
    
    for sym in elf.syms.iter().filter(|s| s.st_type() == STT_FUNC) {
        if let Some(name) = elf.strtab.get(sym.st_name) {
            if name.contains("OpenCommon") {
                return Ok((base + sym.st_value) as Address);
            }
        }
    }
    anyhow::bail!("Symbol not found");
}
 
register_zygisk_module!(DexDumper);​