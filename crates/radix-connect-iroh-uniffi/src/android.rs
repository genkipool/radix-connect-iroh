//! Android-only JNI entry point.
//!
//! iroh resolves the relay's host name with the system DNS servers, which on Android
//! can only be read through the Java `ConnectivityManager`. That needs the JavaVM and
//! the application `Context`, which uniffi (JNA) does not hand to native code, so the
//! Kotlin `RadixConnectIrohAndroid.installAndroidContext(context)` calls this function
//! through plain JNI once per process. Without it iroh falls back to public resolvers.

use std::sync::Once;

use jni::JNIEnv;
use jni::objects::{JClass, JObject};

static INSTALL: Once = Once::new();

/// JNI implementation of `RadixConnectIrohAndroid.nativeInstall(Context)`, called by
/// `installAndroidContext` with the application context.
// Looked up by the JVM through its symbol name, hence `pub` in a private module.
#[allow(unreachable_pub)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_radixdlt_connect_iroh_RadixConnectIrohAndroid_nativeInstall(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    context: JObject<'_>,
) {
    // A panic must not unwind into the JVM.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        INSTALL.call_once(|| {
            let (Ok(vm), Ok(context)) = (env.get_java_vm(), env.new_global_ref(context)) else {
                tracing::warn!("could not install the Android context; iroh will use public DNS");
                return;
            };
            // SAFETY: the JavaVM outlives every native call, and the global reference is
            // leaked on purpose below so the application context stays valid until the
            // process exits, as `install_android_jni_context` requires.
            unsafe {
                iroh::dns::install_android_jni_context(
                    vm.get_java_vm_pointer().cast(),
                    context.as_obj().as_raw().cast(),
                );
            }
            std::mem::forget(context);
        });
    }));
}
