mod cron_macro_codegen;

extern crate proc_macro;
use cron_macro_codegen::impl_method_cron;
use proc_macro::TokenStream;

///
/// for example:
///
///     #[cron("* */10 * * * *")]
///     fn func(){...}
///     The scheduling format is:
///         sec   min   hour   day of month   month   day of week   year
///         *     *     *      *              *       *             *
///     Time is specified for UTC and not your local timezone.
///
///     example:
///     0 0 * * * * // top of every hour of every day
///     0 0/30 8-10 * * * //8:00, 8:30, 9:00, 9:30, 10:00 and 10:30 every day
///     0 0 8-10 * * * 2022 // every ten seconds at 2022
///
///
///     lazy_static::lazy_static!{
///         static ref CONFIG: T = T::new();
///     }
///
///     #[cron("${CONFIG.cron}")]
///     fn func() ->{...}
///
///
#[proc_macro_attribute]
pub fn cron(attr: TokenStream, input: TokenStream) -> TokenStream {
    impl_method_cron(attr, input)
}
