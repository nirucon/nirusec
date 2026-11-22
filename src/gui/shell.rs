//! The event loop shared by the NIRU tools ported from egui: one X window,
//! the canvas, live theme reload and zero work while idle. It sleeps in
//! poll() on the X connection, an eventfd that background threads write to
//! when their work is done, and inotify on the NIRUWM configuration. A timer
//! runs only when the program asks for one.
use super::canvas::Canvas;
use super::text::Text;
use super::theme::{self, Theme};
use super::ui::{KeyEv, KeyUse, State, Ui};
use super::x::{Res, X};
use std::os::fd::AsRawFd;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{Atom, KeyButMask};
use x11rb::protocol::Event;

pub trait App {
    /// Describe the whole window for one frame.
    fn build(&mut self, ui: &mut Ui);
    /// A key before the widgets see it; true when it was used.
    fn key(&mut self, _k: &KeyEv, _st: &mut State) -> bool {
        false
    }
    /// A key the widgets did not use; true when it was used.
    fn key_late(&mut self, _k: &KeyEv, _st: &mut State) -> bool {
        false
    }
    /// Background work signalled the waker; true to redraw.
    fn poll(&mut self) -> bool {
        false
    }
    /// When `tick` should run next (None: never).
    fn next_tick(&self) -> Option<Instant> {
        None
    }
    fn tick(&mut self) -> bool {
        false
    }
    /// A modal layer is shown; only it takes input.
    fn modal(&self) -> bool {
        false
    }
    fn quit(&mut self) {}
}

/// Wakes the event loop from another thread.
#[derive(Clone, Copy, Debug)]
pub struct Waker(i32);

impl Waker {
    pub fn wake(&self) {
        let one: u64 = 1;
        unsafe { libc::write(self.0, &one as *const u64 as *const libc::c_void, 8) };
    }
}

static WAKE_FD: OnceLock<i32> = OnceLock::new();

pub fn waker() -> Waker {
    Waker(
        *WAKE_FD
            .get_or_init(|| unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) }),
    )
}

pub struct Opts {
    pub title: &'static str,
    pub class: &'static str,
    pub size: (u16, u16),
    pub min: (i32, i32),
    pub icon: char,
    /// Print "NAME: first frame after N ms" when this variable is set.
    pub timing_env: &'static str,
}

fn watch(ino: i32) {
    use std::os::unix::ffi::OsStrExt;
    for dir in theme::watch_dirs() {
        if let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) {
            unsafe {
                libc::inotify_add_watch(
                    ino,
                    c.as_ptr(),
                    libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_CREATE | libc::IN_DELETE,
                )
            };
        }
    }
}

fn drain(fd: i32) {
    let mut buf = [0u8; 4096];
    while unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) } > 0 {}
}

pub fn run(app: &mut dyn App, o: Opts, started: Instant) -> Res<()> {
    let mut x = X::open(o.size.0, o.size.1, o.min, o.title, o.class)?;
    let mut root_name = x.root_theme();
    let mut theme: Theme = theme::load(root_name.as_deref());
    let mut text = Text::new(theme.font_path.as_deref())?;
    let _ = x.set_icon(&super::logo::window_icons(&theme.palette, o.icon));
    x.map()?;
    let wake = waker().0;
    let ino = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if ino >= 0 {
        watch(ino);
    }
    let theme_atom: Atom = x.atoms.niruwm_theme;
    let xfd = x.c.stream().as_raw_fd();
    let mut st = State::default();
    let mut cv = Canvas::new(o.size.0 as i32, o.size.1 as i32);
    let mut dirty = true;
    let mut shown = false;
    let mut clip_text = String::new();
    let mut reload: Option<Instant> = None;
    let mut mapped_size = false;
    loop {
        while let Some(ev) = x.c.poll_for_event()? {
            match ev {
                Event::Expose(e) if e.count == 0 => dirty = true,
                Event::ConfigureNotify(e) if e.window == x.win => {
                    let (w, h) = (e.width as i32, e.height as i32);
                    if w != cv.w || h != cv.h || !mapped_size {
                        mapped_size = true;
                        cv.resize(w, h);
                        dirty = true;
                    }
                }
                Event::KeyPress(e) => {
                    let ks = x.keysym(e.detail, e.state);
                    if (0xffe1..=0xffee).contains(&ks) || ks == 0xfe03 {
                        continue;
                    }
                    let k = KeyEv::new(
                        ks,
                        e.state.contains(KeyButMask::CONTROL),
                        e.state.contains(KeyButMask::SHIFT),
                        e.state.contains(KeyButMask::MOD1),
                    );
                    if app.key(&k, &mut st) {
                        dirty = true;
                    } else {
                        match st.key(&k) {
                            KeyUse::Used => dirty = true,
                            KeyUse::Paste => {
                                let _ = x.request_clipboard();
                            }
                            KeyUse::Ignored => {
                                if app.key_late(&k, &mut st) {
                                    dirty = true;
                                }
                            }
                        }
                    }
                }
                Event::ButtonPress(e) => {
                    if st.press(e.event_x as i32, e.event_y as i32, e.detail) {
                        dirty = true;
                    }
                }
                Event::MotionNotify(e) => {
                    if st.motion(e.event_x as i32, e.event_y as i32) {
                        dirty = true;
                    }
                    x.set_pointer(st.pointer());
                }
                Event::LeaveNotify(_) => {
                    if st.leave() {
                        dirty = true;
                    }
                }
                Event::ClientMessage(e) => {
                    if e.format == 32 && e.data.as_data32()[0] == x.atoms.wm_delete {
                        st.quit = true;
                    }
                }
                Event::PropertyNotify(e) if e.window == x.root && e.atom == theme_atom => {
                    reload = Some(Instant::now());
                }
                Event::SelectionNotify(e) => {
                    if e.property != x11rb::NONE {
                        if let Some(t) = x.take_selection() {
                            st.paste(&t);
                            dirty = true;
                        }
                    }
                }
                Event::SelectionRequest(e) => {
                    let _ = x.answer_text(&e, &clip_text);
                }
                Event::SelectionClear(_) => clip_text.clear(),
                _ => {}
            }
        }
        if st.quit {
            app.quit();
            return Ok(());
        }
        let now = Instant::now();
        if reload.is_some_and(|t| now >= t) {
            reload = None;
            root_name = x.root_theme();
            let new = theme::load(root_name.as_deref());
            if new != theme {
                if new.font_path != theme.font_path {
                    if let Ok(t) = Text::new(new.font_path.as_deref()) {
                        text = t;
                    }
                }
                theme = new;
                let _ = x.set_icon(&super::logo::window_icons(&theme.palette, o.icon));
                dirty = true;
            }
        }
        if app.next_tick().is_some_and(|t| now >= t) && app.tick() {
            dirty = true;
        }
        if dirty {
            dirty = false;
            for _ in 0..5 {
                st.modal = app.modal();
                st.again = false;
                let mut ui = st.begin(&mut text, &theme, cv.w, cv.h);
                let bg = ui.pal.background;
                let screen = ui.screen;
                ui.paint_fill(screen, bg);
                app.build(&mut ui);
                ui.finish(&mut cv);
                if !st.again || st.quit {
                    break;
                }
            }
            if st.quit {
                continue;
            }
            if let Some(t) = st.copy.take() {
                clip_text = t;
                let _ = x.own_clipboard();
            }
            x.set_pointer(st.pointer());
            x.present(&cv)?;
            if !shown {
                shown = true;
                if std::env::var_os(o.timing_env).is_some() {
                    eprintln!(
                        "{}: first frame after {:.1} ms",
                        o.class,
                        started.elapsed().as_secs_f64() * 1000.0
                    );
                }
            }
            continue;
        }
        x.c.flush()?;
        let mut timeout: i32 = -1;
        let mut at = |t: Instant| {
            let ms = t.saturating_duration_since(Instant::now()).as_millis() as i32 + 1;
            timeout = if timeout < 0 { ms } else { timeout.min(ms) };
        };
        if let Some(t) = reload {
            at(t);
        }
        if let Some(t) = app.next_tick() {
            at(t.max(Instant::now()));
        }
        let mut fds = [
            libc::pollfd {
                fd: xfd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: ino,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = if ino >= 0 { 3 } else { 2 };
        unsafe { libc::poll(fds.as_mut_ptr(), n, timeout) };
        if fds[1].revents & libc::POLLIN != 0 {
            drain(wake);
            if app.poll() {
                dirty = true;
            }
        }
        if n == 3 && fds[2].revents & libc::POLLIN != 0 {
            drain(ino);
            // A theme directory created after start is watched from now on.
            watch(ino);
            reload = Some(Instant::now() + Duration::from_millis(150));
        }
    }
}
