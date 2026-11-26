//! Нативная иконка в системном трее Windows (pure `windows-sys`) и хелперы управления окном.

use std::sync::{Arc, Mutex};

#[cfg(target_os = "windows")]
mod imp {
    use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread::JoinHandle;

    use windows_sys::Win32::Foundation::{
        BOOL, CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HMODULE, HWND, LPARAM, LRESULT,
        POINT, WPARAM,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::Shell::{
        NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
        Shell_NotifyIconW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AllowSetForegroundWindow, AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW,
        DestroyMenu, DestroyWindow, DispatchMessageW, EnumThreadWindows, FindWindowW, GW_OWNER,
        GetCursorPos, GetMessageW, GetWindow, GetWindowTextW, IDI_APPLICATION, IsIconic, IsWindow,
        IsWindowVisible, IsZoomed, LoadIconW, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG,
        PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SW_HIDE,
        SW_MAXIMIZE, SW_RESTORE, SW_SHOW, SetForegroundWindow, ShowWindow, ShowWindowAsync,
        TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WM_APP,
        WM_CANCELMODE, WM_CLOSE, WM_COMMAND, WM_CONTEXTMENU, WM_DESTROY, WM_ENDSESSION,
        WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_NULL, WM_QUERYENDSESSION, WM_RBUTTONUP, WNDCLASSW,
        WS_OVERLAPPED,
    };

    const WM_APP_TRAY: u32 = WM_APP + 1;
    const WM_APP_UPDATE_TIP: u32 = WM_APP + 2;
    const WM_APP_SHOW_MAIN: u32 = WM_APP + 3;

    const TRAY_ICON_ID: u32 = 1;
    const IDM_SHOW: usize = 1001;
    const IDM_TOGGLE_VPN: usize = 1002;
    const IDM_EXIT: usize = 1003;

    static EVENT_QUEUE: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();
    static INSTANCE_MUTEX: AtomicIsize = AtomicIsize::new(0);
    static MAIN_HWND: AtomicIsize = AtomicIsize::new(0);
    static TRAY_HWND: AtomicIsize = AtomicIsize::new(0);
    static TASKBAR_CREATED_MSG: AtomicU32 = AtomicU32::new(0);
    static CONNECTED: AtomicBool = AtomicBool::new(false);
    static LANG_EN: AtomicBool = AtomicBool::new(false);
    static TRAY_THREAD: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);
    static STARTED: AtomicBool = AtomicBool::new(false);
    static SHUTDOWN_REQ: AtomicBool = AtomicBool::new(false);

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn push_event(ev: &str) {
        if let Some(q) = EVENT_QUEUE.get()
            && let Ok(mut guard) = q.lock()
        {
            guard.push(ev.to_string());
        }
    }

    fn tooltip_text() -> String {
        let conn = CONNECTED.load(Ordering::Relaxed);
        let en = LANG_EN.load(Ordering::Relaxed);
        match (en, conn) {
            (true, true) => "Tachyon — Connected".to_string(),
            (true, false) => "Tachyon — Disconnected".to_string(),
            (false, true) => "Tachyon — Подключено".to_string(),
            (false, false) => "Tachyon — Отключено".to_string(),
        }
    }

    unsafe fn fill_notify_icon_data(hwnd: HWND, include_icon: bool) -> NOTIFYICONDATAW {
        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ICON_ID;
        nid.uFlags = NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_APP_TRAY;
        if include_icon {
            let hinst: HMODULE = unsafe { GetModuleHandleW(std::ptr::null()) };
            let mut hicon = unsafe { LoadIconW(hinst, std::ptr::without_provenance::<u16>(1)) };
            if hicon.is_null() {
                hicon = unsafe { LoadIconW(std::ptr::null_mut(), IDI_APPLICATION) };
            }
            nid.hIcon = hicon;
            nid.uFlags |= NIF_ICON;
        }
        let tip: Vec<u16> = tooltip_text().encode_utf16().collect();
        let copy_len = tip.len().min(nid.szTip.len().saturating_sub(1));
        nid.szTip[..copy_len].copy_from_slice(&tip[..copy_len]);
        nid.szTip[copy_len] = 0;
        nid
    }

    unsafe fn add_or_update_tray_icon(hwnd: HWND, add: bool) {
        let nid = unsafe { fill_notify_icon_data(hwnd, add) };
        let msg = if add { NIM_ADD } else { NIM_MODIFY };
        unsafe {
            let _ = Shell_NotifyIconW(msg, &nid);
        }
    }

    unsafe fn remove_tray_icon(hwnd: HWND) {
        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ICON_ID;
        unsafe {
            let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
        }
    }

    unsafe fn show_context_menu(hwnd: HWND) {
        let hmenu = unsafe { CreatePopupMenu() };
        if hmenu.is_null() {
            return;
        }
        let conn = CONNECTED.load(Ordering::Relaxed);
        let en = LANG_EN.load(Ordering::Relaxed);

        let status_label = to_wide(match (en, conn) {
            (true, true) => "Status: Connected",
            (true, false) => "Status: Disconnected",
            (false, true) => "Статус: Подключено",
            (false, false) => "Статус: Отключено",
        });
        let show_label = to_wide(if en {
            "Open Tachyon"
        } else {
            "Открыть Tachyon"
        });
        let toggle_label = to_wide(match (en, conn) {
            (true, true) => "Disconnect",
            (true, false) => "Connect",
            (false, true) => "Отключить",
            (false, false) => "Подключить",
        });
        let exit_label = to_wide(if en { "Exit" } else { "Выход" });

        unsafe {
            AppendMenuW(hmenu, MF_STRING | MF_GRAYED, 0, status_label.as_ptr());
            AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
            AppendMenuW(hmenu, MF_STRING, IDM_SHOW, show_label.as_ptr());
            AppendMenuW(hmenu, MF_STRING, IDM_TOGGLE_VPN, toggle_label.as_ptr());
            AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
            AppendMenuW(hmenu, MF_STRING, IDM_EXIT, exit_label.as_ptr());

            let mut pt = POINT { x: 0, y: 0 };
            let _ = GetCursorPos(&mut pt);
            let _ = SetForegroundWindow(hwnd);
            let _ = TrackPopupMenu(
                hmenu,
                TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
                pt.x,
                pt.y,
                0,
                hwnd,
                std::ptr::null(),
            );
            let _ = PostMessageW(hwnd, WM_NULL, 0, 0);
            let _ = DestroyMenu(hmenu);
        }
    }

    unsafe extern "system" fn tray_wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let taskbar_msg = TASKBAR_CREATED_MSG.load(Ordering::Relaxed);
        if taskbar_msg != 0 && msg == taskbar_msg {
            unsafe { add_or_update_tray_icon(hwnd, true) };
            return 0;
        }

        match msg {
            WM_APP_TRAY => {
                let mouse_msg = (lparam as u32) & 0xFFFF;
                if mouse_msg == WM_LBUTTONUP || mouse_msg == WM_LBUTTONDBLCLK {
                    show_from_tray();
                } else if mouse_msg == WM_RBUTTONUP || mouse_msg == WM_CONTEXTMENU {
                    unsafe { show_context_menu(hwnd) };
                }
                0
            }
            WM_APP_UPDATE_TIP => {
                unsafe { add_or_update_tray_icon(hwnd, false) };
                0
            }
            WM_APP_SHOW_MAIN => {
                show_from_tray();
                0
            }
            WM_COMMAND => {
                let cmd = wparam & 0xFFFF;
                match cmd {
                    IDM_SHOW => show_from_tray(),
                    IDM_TOGGLE_VPN => push_event("tray:toggle-vpn"),
                    IDM_EXIT => push_event("tray:exit"),
                    _ => {}
                }
                0
            }
            WM_QUERYENDSESSION => 1,
            WM_ENDSESSION => {
                if wparam != 0 {
                    push_event("tray:exit");
                }
                0
            }
            WM_CLOSE => {
                if SHUTDOWN_REQ.load(Ordering::SeqCst) {
                    unsafe {
                        let _ = DestroyWindow(hwnd);
                    }
                } else {
                    // Внешнее закрытие (например, WiX CloseApplication при обновлении MSI):
                    // даём основному приложению корректно отключить туннель и выйти.
                    push_event("tray:exit");
                }
                0
            }
            WM_DESTROY => {
                unsafe {
                    remove_tray_icon(hwnd);
                    PostQuitMessage(0);
                }
                TRAY_HWND.store(0, Ordering::SeqCst);
                0
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    pub fn init(event_queue: Arc<Mutex<Vec<String>>>) {
        let _ = EVENT_QUEUE.set(event_queue);
        if STARTED.swap(true, Ordering::AcqRel) {
            return;
        }
        let handle = std::thread::Builder::new()
            .name("tachyon-tray".to_string())
            .spawn(|| unsafe {
                let hinst: HMODULE = GetModuleHandleW(std::ptr::null());
                let cls_name = to_wide("TachyonTrayMsgWindow");
                let wc = WNDCLASSW {
                    style: 0,
                    lpfnWndProc: Some(tray_wndproc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinst,
                    hIcon: std::ptr::null_mut(),
                    hCursor: std::ptr::null_mut(),
                    hbrBackground: std::ptr::null_mut(),
                    lpszMenuName: std::ptr::null(),
                    lpszClassName: cls_name.as_ptr(),
                };
                let _ = RegisterClassW(&wc);

                let tb_name = to_wide("TaskbarCreated");
                TASKBAR_CREATED_MSG
                    .store(RegisterWindowMessageW(tb_name.as_ptr()), Ordering::Relaxed);

                let win_title = to_wide("Tachyon Tray");
                let hwnd = CreateWindowExW(
                    0,
                    cls_name.as_ptr(),
                    win_title.as_ptr(),
                    WS_OVERLAPPED,
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    hinst,
                    std::ptr::null(),
                );
                if hwnd.is_null() {
                    return;
                }
                TRAY_HWND.store(hwnd as isize, Ordering::SeqCst);
                if SHUTDOWN_REQ.load(Ordering::SeqCst) {
                    let _ = DestroyWindow(hwnd);
                    return;
                }
                add_or_update_tray_icon(hwnd, true);

                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            })
            .ok();
        if let Ok(mut guard) = TRAY_THREAD.lock() {
            *guard = handle;
        }
    }

    unsafe extern "system" fn enum_thread_win_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let out_ptr = lparam as *mut isize;
        if out_ptr.is_null() {
            return 0;
        }
        let has_owner = !unsafe { GetWindow(hwnd, GW_OWNER) }.is_null();
        if has_owner {
            return 1;
        }
        let tray_h = TRAY_HWND.load(Ordering::SeqCst);
        if (hwnd as isize) == tray_h {
            return 1;
        }
        let mut buf = [0u16; 64];
        let len = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
        let title = if len > 0 {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            String::new()
        };
        if title.starts_with("Tachyon") {
            unsafe {
                *out_ptr = hwnd as isize;
            }
            return 0;
        }
        if unsafe { *out_ptr == 0 && IsWindowVisible(hwnd) != 0 } {
            unsafe {
                *out_ptr = hwnd as isize;
            }
        }
        1
    }

    pub fn register_main_window() {
        let existing = MAIN_HWND.load(Ordering::Acquire);
        if existing != 0 && unsafe { IsWindow(existing as HWND) } != 0 {
            return;
        }
        let mut found: isize = 0;
        unsafe {
            let tid = GetCurrentThreadId();
            let _ = EnumThreadWindows(
                tid,
                Some(enum_thread_win_cb),
                (&mut found as *mut isize) as LPARAM,
            );
        }
        if found != 0 {
            MAIN_HWND.store(found, Ordering::Release);
        }
    }

    fn resolve_main_hwnd() -> HWND {
        let hwnd = MAIN_HWND.load(Ordering::Acquire) as HWND;
        if !hwnd.is_null() && unsafe { IsWindow(hwnd) } != 0 {
            hwnd
        } else {
            std::ptr::null_mut()
        }
    }

    pub fn toggle_maximize_window() -> bool {
        register_main_window();
        let hwnd = resolve_main_hwnd();
        if hwnd.is_null() {
            return false;
        }
        unsafe {
            let zoomed = IsZoomed(hwnd) != 0;
            let _ = ShowWindowAsync(hwnd, if zoomed { SW_RESTORE } else { SW_MAXIMIZE });
        }
        true
    }

    pub fn hide_to_tray() -> bool {
        register_main_window();
        let hwnd = resolve_main_hwnd();
        if hwnd.is_null() {
            return false;
        }
        unsafe {
            let _ = ShowWindow(hwnd, SW_HIDE);
        }
        true
    }

    pub fn show_from_tray() {
        let hwnd = resolve_main_hwnd();
        if !hwnd.is_null() {
            unsafe {
                if IsIconic(hwnd) != 0 {
                    let _ = ShowWindowAsync(hwnd, SW_RESTORE);
                } else {
                    let _ = ShowWindowAsync(hwnd, SW_SHOW);
                }
                let _ = SetForegroundWindow(hwnd);
            }
        }
        push_event("tray:show");
    }

    pub fn update_status(connected: bool, is_en: bool) {
        let prev_conn = CONNECTED.swap(connected, Ordering::Relaxed);
        let prev_en = LANG_EN.swap(is_en, Ordering::Relaxed);
        if prev_conn == connected && prev_en == is_en {
            return;
        }
        let hwnd = TRAY_HWND.load(Ordering::SeqCst) as HWND;
        if !hwnd.is_null() {
            unsafe {
                let _ = PostMessageW(hwnd, WM_APP_UPDATE_TIP, 0, 0);
            }
        }
    }

    pub fn acquire_single_instance_or_focus_existing() -> bool {
        unsafe extern "system" {
            fn CreateMutexW(
                lp_mutex_attributes: *const std::ffi::c_void,
                b_initial_owner: i32,
                lp_name: *const u16,
            ) -> windows_sys::Win32::Foundation::HANDLE;
        }
        let name = to_wide("Local\\TachyonDesktopSingleInstance");
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return true;
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe {
                let _ = CloseHandle(handle);
                let _ = AllowSetForegroundWindow(0xFFFF_FFFF);
                let tray_cls = to_wide("TachyonTrayMsgWindow");
                let tray_hwnd = FindWindowW(tray_cls.as_ptr(), std::ptr::null());
                if !tray_hwnd.is_null() {
                    let _ = PostMessageW(tray_hwnd, WM_APP_SHOW_MAIN, 0, 0);
                } else {
                    let win_title = to_wide("Tachyon");
                    let win_hwnd = FindWindowW(std::ptr::null(), win_title.as_ptr());
                    if !win_hwnd.is_null() {
                        if IsIconic(win_hwnd) != 0 {
                            let _ = ShowWindowAsync(win_hwnd, SW_RESTORE);
                        } else {
                            let _ = ShowWindowAsync(win_hwnd, SW_SHOW);
                        }
                        let _ = SetForegroundWindow(win_hwnd);
                    }
                }
            }
            return false;
        }
        INSTANCE_MUTEX.store(handle as isize, Ordering::Release);
        true
    }

    pub fn shutdown() {
        SHUTDOWN_REQ.store(true, Ordering::SeqCst);
        let hwnd = TRAY_HWND.load(Ordering::SeqCst) as HWND;
        if !hwnd.is_null() {
            unsafe {
                let _ = PostMessageW(hwnd, WM_CANCELMODE, 0, 0);
                let _ = PostMessageW(hwnd, WM_CLOSE, 0, 0);
            }
        }
        if let Ok(mut guard) = TRAY_THREAD.lock()
            && let Some(jh) = guard.take()
            && std::thread::current().id() != jh.thread().id()
        {
            let _ = jh.join();
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod imp {
    use std::sync::{Arc, Mutex};

    #[cfg(unix)]
    static LOCK_FILE: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

    pub fn acquire_single_instance_or_focus_existing() -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let lock_path = crate::vpn::app_data_dir().join("tachyon.lock");
            if let Ok(file) = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&lock_path)
            {
                let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error().raw_os_error();
                    if err == Some(libc::EWOULDBLOCK) || err == Some(libc::EAGAIN) {
                        return false;
                    }
                }
                let _ = LOCK_FILE.set(file);
            }
        }
        true
    }

    pub fn init(_event_queue: Arc<Mutex<Vec<String>>>) {}
    pub fn register_main_window() {}
    pub fn toggle_maximize_window() -> bool {
        false
    }
    pub fn hide_to_tray() -> bool {
        false
    }
    #[allow(dead_code)]
    pub fn show_from_tray() {}
    pub fn update_status(_connected: bool, _is_en: bool) {}
    pub fn shutdown() {}
}

pub fn acquire_single_instance_or_focus_existing() -> bool {
    imp::acquire_single_instance_or_focus_existing()
}

pub fn init(event_queue: Arc<Mutex<Vec<String>>>) {
    imp::init(event_queue);
}

pub fn register_main_window() {
    imp::register_main_window();
}

pub fn toggle_maximize_window() -> bool {
    imp::toggle_maximize_window()
}

pub fn hide_to_tray() -> bool {
    imp::hide_to_tray()
}

#[allow(dead_code)]
pub fn show_from_tray() {
    imp::show_from_tray();
}

pub fn update_status(connected: bool, is_en: bool) {
    imp::update_status(connected, is_en);
}

pub fn shutdown() {
    imp::shutdown();
}
