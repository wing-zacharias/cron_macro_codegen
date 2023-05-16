mod cron_macro_codegen;

extern crate proc_macro;
use cron_macro_codegen::impl_method_cron;
use proc_macro::TokenStream;

///
/// for example:
///
///     #[cron("* */10 * * * *")]
///     async fn func(task: T) -> Result<(),Error> {}
///
///     lazy_static::lazy_static!{
///         static ref CONFIG: T = T::new();
///     }
///
///     #[cron("${CONFIG.cron}")]
///     async fn func(task: T) -> Result<(),Error> {}
///
#[proc_macro_attribute]
pub fn cron(attr: TokenStream, input: TokenStream) -> TokenStream {
    impl_method_cron(attr, input)
}
