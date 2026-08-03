//! UI test: a `SecurityContext` must not outlive the `GssName` it targets.
//!
//! Today `SecurityContext` stores a raw `gss_name_t` with no lifetime tie, so
//! this program compiles and the context is left holding a dangling pointer.
//! After the fix the borrow checker must reject it.

use gss_token_helper::gss::{self, InitSecContextOpts};

fn main() {
    let opts = InitSecContextOpts::default();

    let ctx = {
        let name = gss::import_name("HTTP@example.com").expect("import");
        gss::SecurityContext::new(&name, &opts)
        // `name` is dropped here, releasing the underlying gss_name_t.
    };

    drop(ctx);
}
