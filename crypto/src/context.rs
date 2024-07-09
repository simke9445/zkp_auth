use openssl::bn::BigNumContext;
use std::cell::RefCell;

thread_local! {
    pub static BN_CTX: RefCell<BigNumContext> = RefCell::new(BigNumContext::new().unwrap());
}

pub fn with_bn_ctx<F, R>(f: F) -> R
where
    F: FnOnce(&mut BigNumContext) -> R,
{
    BN_CTX.with(|ctx| f(&mut ctx.borrow_mut()))
}
