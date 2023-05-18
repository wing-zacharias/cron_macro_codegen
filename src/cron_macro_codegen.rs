use cron::Schedule;
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use regex::Regex;
use std::str::FromStr;
use syn::{parse_macro_input, AttributeArgs, ItemFn, NestedMeta, ReturnType};

lazy_static::lazy_static! {
    static ref CRON_ATTR_REGEX_OF_REF:String = r#"^\$\{(.*?)\}$"#.to_string();
}

fn input_and_compile_error(mut item: TokenStream, err: syn::Error) -> TokenStream {
    let compile_err = TokenStream::from(err.to_compile_error());
    item.extend(compile_err);
    item
}

pub struct Args {
    pub cron: syn::LitStr,
}

impl Args {
    fn new(args: AttributeArgs) -> syn::Result<Self> {
        if args.len() != 1 {
            return Err(syn::Error::new(
                Span::call_site(),
                "[cron] Incorrect macro parameter,example  #[cron(\"* */10 * * * *\")],#[cron(\"${CONFIG.cron}\")]!"
                    .to_string(),
            ));
        }

        let cron = match args.get(0).unwrap() {
            NestedMeta::Lit(syn::Lit::Str(lit)) => Some(lit),
            NestedMeta::Meta(arg) => {
                return Err(syn::Error::new_spanned(arg, "error2!"));
            }
            arg => {
                return Err(syn::Error::new_spanned(arg, "error3!"));
            }
        };
        Ok(Args {
            cron: cron.unwrap().to_owned(),
        })
    }
}

pub(crate) fn find_return_type(target_fn: &ItemFn) -> proc_macro2::TokenStream {
    let mut return_ty = target_fn.sig.output.to_token_stream();
    match &target_fn.sig.output {
        ReturnType::Type(_, b) => {
            return_ty = b.to_token_stream();
        }
        _ => {}
    }
    let s = format!("{}", return_ty);
    if !s.contains(":: Result") && !s.starts_with("Result") {
        return_ty = quote! {
             core::Result <#return_ty>
        };
    }
    return_ty
}

pub(crate) fn impl_method_cron(attr: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as AttributeArgs);
    let ast = match syn::parse::<ItemFn>(input.clone()) {
        Ok(ast) => ast,
        Err(err) => return input_and_compile_error(input, err),
    };
    let args = Args::new(args);
    let str_cron = args.unwrap().cron.token().to_string().replace("\"", "");
    let _func_vis = &ast.vis;

    let _func_decl = &ast.sig;
    let _func_name = &_func_decl.ident;
    let _func_generics = &_func_decl.generics;
    let _func_inputs = &_func_decl.inputs;
    let _func_rtp = find_return_type(&ast);
    let _func_block = &ast.block;

    let reg_ref = Regex::new(CRON_ATTR_REGEX_OF_REF.as_str()).unwrap();
    let _time_of_cron = if reg_ref.is_match(&str_cron) {
        let res = reg_ref.captures(&str_cron).unwrap();
        TokenStream2::from_str(format!("{}.as_str()", res.get(1).unwrap().as_str()).as_str())
            .unwrap()
    } else {
        if Schedule::try_from(str_cron.as_str()).is_err() {
            let err_msg = "[cron] Incorrect macro parameter,example  #[cron(\"* */10 * * * *\")],#[cron(\"${CONFIG.cron}\")]!".to_string();
            panic!("{}", err_msg);
        }
        quote! {#str_cron}
    };

    let _uid = uuid::Uuid::new_v4().to_string().replace("-", "");
    let _job_name = Ident::new(format!("_job_{}", _uid).as_str(), Span::call_site());
    let _job_block = quote! {
        let #_job_name = Job::new_async(#_time_of_cron,move|_uuid,_lock|{
            Box::pin(async move{
                #_func_block
            })
        }).unwrap();
        sched.add(#_job_name).await.unwrap();
    };

    let _task_start_block_header: TokenStream2 = quote! {
        let sched = JobScheduler::new().await.unwrap();
    };

    let _task_start_block_tail: TokenStream2 = quote! {
        #[cfg(feature = "signal")]
        sched.shutdown_on_ctrl_c();
        sched.start().await.unwrap();
    };

    let stream = quote! {

        #_func_vis async fn #_func_name #_func_generics(){
            use tokio_cron_scheduler::{Job, JobScheduler};
            #_task_start_block_header
            #_job_block
            #_task_start_block_tail
        }
    };
    stream.into()
}
