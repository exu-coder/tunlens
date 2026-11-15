//! JNI surface for `dev.tunlens.NativeBridge`.
//!
//! Deliberately mirrors only the observation half of the original app's
//! `NativeBridge`: start/stop the capture path and stream events to Kotlin.
//! There is no `setKey`, no `editAndSend`, and no signature gate.

use crate::events::{set_sink, FlowEvent, Sink};
use crate::{socks5, tun};
use jni::objects::{GlobalRef, JObject, JValue};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

static VM: OnceLock<JavaVM> = OnceLock::new();
static LISTENER: Mutex<Option<GlobalRef>> = Mutex::new(None);
static RUNNING: AtomicBool = AtomicBool::new(false);
static SHUTDOWN: OnceLock<Arc<AtomicBool>> = OnceLock::new();

fn shutdown() -> Arc<AtomicBool> {
    SHUTDOWN
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

fn bool_to_jni(value: bool) -> jboolean {
    if value {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Build the sink that forwards each event to `Listener.onEvent(String)`.
fn attach_sink(env: &mut JNIEnv<'_>) {
    if let Ok(vm) = env.get_java_vm() {
        let _ = VM.set(vm);
    }
    let sink: Sink = Arc::new(|event: FlowEvent| {
        let Some(vm) = VM.get() else { return };
        let Ok(mut env) = vm.attach_current_thread() else { return };
        let Ok(payload) = serde_json::to_string(&event) else { return };
        let Ok(text) = env.new_string(payload) else { return };
        let guard = match LISTENER.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if let Some(listener) = guard.as_ref() {
            let _ = env.call_method(
                listener.as_obj(),
                "onEvent",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&text)],
            );
        }
    });
    set_sink(Some(sink));
}

#[no_mangle]
pub extern "system" fn Java_dev_tunlens_NativeBridge_version(
    env: JNIEnv<'_>,
    _class: JObject,
) -> jstring {
    let text = format!("{} {}", crate::ENGINE_NAME, crate::ENGINE_VERSION);
    match env.new_string(text) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_tunlens_NativeBridge_setListener(
    mut env: JNIEnv<'_>,
    _class: JObject,
    listener: JObject<'_>,
) -> jboolean {
    let Ok(reference) = env.new_global_ref(listener) else {
        return JNI_FALSE;
    };
    if let Ok(mut guard) = LISTENER.lock() {
        *guard = Some(reference);
    }
    attach_sink(&mut env);
    JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_dev_tunlens_NativeBridge_clearListener(
    _env: JNIEnv<'_>,
    _class: JObject,
) {
    if let Ok(mut guard) = LISTENER.lock() {
        *guard = None;
    }
    set_sink(None);
}

#[no_mangle]
pub extern "system" fn Java_dev_tunlens_NativeBridge_startSocks(
    mut env: JNIEnv<'_>,
    _class: JObject,
    port: jint,
) -> jboolean {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return JNI_TRUE;
    }
    attach_sink(&mut env);
    let flag = shutdown();
    flag.store(false, Ordering::SeqCst);
    let listen = std::net::SocketAddr::from(([127, 0, 0, 1], port as u16));
    thread::spawn(move || {
        if let Err(err) = socks5::serve(listen, flag) {
            eprintln!("[jni] socks5 listener failed: {err}");
        }
    });
    JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_dev_tunlens_NativeBridge_stopSocks(_env: JNIEnv<'_>, _class: JObject) {
    shutdown().store(true, Ordering::SeqCst);
    RUNNING.store(false, Ordering::SeqCst);
}

#[no_mangle]
pub extern "system" fn Java_dev_tunlens_NativeBridge_startTun(
    mut env: JNIEnv<'_>,
    _class: JObject,
    fd: jint,
) -> jboolean {
    attach_sink(&mut env);
    RUNNING.store(true, Ordering::SeqCst);
    let flag = shutdown();
    flag.store(false, Ordering::SeqCst);
    let config = tun::TunConfig::default();
    thread::spawn(move || {
        if let Err(err) = tun::run(fd, config, flag) {
            eprintln!("[jni] tun bridge failed: {err}");
        }
    });
    JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_dev_tunlens_NativeBridge_stopTun(_env: JNIEnv<'_>, _class: JObject) {
    shutdown().store(true, Ordering::SeqCst);
    RUNNING.store(false, Ordering::SeqCst);
}

#[no_mangle]
pub extern "system" fn Java_dev_tunlens_NativeBridge_isRunning(
    _env: JNIEnv<'_>,
    _class: JObject,
) -> jboolean {
    bool_to_jni(RUNNING.load(Ordering::SeqCst))
}

#[no_mangle]
pub extern "system" fn Java_dev_tunlens_NativeBridge_connectionCount(
    _env: JNIEnv<'_>,
    _class: JObject,
) -> jint {
    socks5::connection_count() as jint
}
