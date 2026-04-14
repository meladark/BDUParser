use std::{
    env,
    ffi::{CStr, CString, c_char},
    sync::{Once, OnceLock, RwLock},
};

use bdu_parser::{bd::BD, get_excel, get_html, get_pdf};
use log::{LevelFilter, Log, Metadata, Record};
use serde::Serialize;

type LogCallback = extern "C" fn(*const c_char);

struct FfiLogger {
    inner: env_logger::Logger,
}

impl Log for FfiLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        self.inner.log(record);

        let callback = callback_slot().read().ok().and_then(|guard| *guard);
        if let Some(callback) = callback {
            let message = format!("[{} {}] {}", record.level(), record.target(), record.args())
                .replace('\0', " ");
            if let Ok(message) = CString::new(message) {
                callback(message.as_ptr());
            }
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

#[derive(Serialize)]
struct FfiResponse<T> {
    ok: bool,
    data: Option<T>,
    error: Option<String>,
}

fn make_response<T: Serialize>(result: Result<T, String>) -> *mut c_char {
    let payload = match result {
        Ok(data) => FfiResponse {
            ok: true,
            data: Some(data),
            error: None,
        },
        Err(error) => FfiResponse::<T> {
            ok: false,
            data: None,
            error: Some(error),
        },
    };

    match serde_json::to_string(&payload) {
        Ok(json) => CString::new(json)
            .expect("serialized JSON must not contain interior NUL bytes")
            .into_raw(),
        Err(error) => CString::new(format!(
            "{{\"ok\":false,\"data\":null,\"error\":\"failed to serialize response: {}\"}}",
            error
        ))
        .expect("fallback JSON must not contain interior NUL bytes")
        .into_raw(),
    }
}

fn read_required_string(input: *const c_char, field: &str) -> Result<String, String> {
    if input.is_null() {
        return Err(format!("{} is null", field));
    }

    let value = unsafe {
        // The caller must provide a valid NUL-terminated string.
        CStr::from_ptr(input)
    };

    value
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|_| format!("{} is not valid UTF-8", field))
}

fn callback_slot() -> &'static RwLock<Option<LogCallback>> {
    static LOG_CALLBACK: OnceLock<RwLock<Option<LogCallback>>> = OnceLock::new();
    LOG_CALLBACK.get_or_init(|| RwLock::new(None))
}

fn init_ffi_logger() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let mut builder = env_logger::Builder::from_default_env();
        if env::var("RUST_LOG").is_err() {
            builder.filter_level(LevelFilter::Info);
        }
        let logger = FfiLogger {
            inner: builder.build(),
        };
        log::set_max_level(LevelFilter::Trace);
        let _ = log::set_boxed_logger(Box::new(logger));
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn bdu_parser_free_string(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    unsafe {
        // Rebuild the CString so Rust drops the allocation once.
        drop(CString::from_raw(value));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bdu_parser_version() -> *mut c_char {
    CString::new(env!("CARGO_PKG_VERSION"))
        .expect("package version must not contain interior NUL bytes")
        .into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn bdu_parser_set_log_callback(callback: Option<LogCallback>) {
    init_ffi_logger();
    if let Ok(mut slot) = callback_slot().write() {
        *slot = callback;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bdu_parser_update(postgres_url: *const c_char) -> *mut c_char {
    init_ffi_logger();
    let result = (|| {
        let postgres_url = read_required_string(postgres_url, "postgres_url")?;
        let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

        runtime.block_on(async move {
            let db = BD::new(&postgres_url).await?;
            db.update().await?;
            Ok(serde_json::json!({ "updated": true }))
        })
    })();

    make_response(result)
}

#[unsafe(no_mangle)]
pub extern "C" fn bdu_parser_find_json(
    postgres_url: *const c_char,
    sbom_path: *const c_char,
    full: bool,
) -> *mut c_char {
    init_ffi_logger();
    let result = (|| {
        let postgres_url = read_required_string(postgres_url, "postgres_url")?;
        let sbom_path = read_required_string(sbom_path, "sbom_path")?;
        let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

        runtime.block_on(async move {
            let db = BD::new(&postgres_url).await?;
            db.find(&sbom_path, full).await
        })
    })();

    make_response(result)
}

#[unsafe(no_mangle)]
pub extern "C" fn bdu_parser_generate_reports(
    postgres_url: *const c_char,
    sbom_path: *const c_char,
    report_name: *const c_char,
    full: bool,
) -> *mut c_char {
    init_ffi_logger();
    let result = (|| {
        let postgres_url = read_required_string(postgres_url, "postgres_url")?;
        let sbom_path = read_required_string(sbom_path, "sbom_path")?;
        let report_name = read_required_string(report_name, "report_name")?;
        let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

        runtime.block_on(async move {
            let db = BD::new(&postgres_url).await?;
            let vulns = db.find(&sbom_path, full).await?;
            let count = vulns.len();

            if count == 0 {
                return Ok(serde_json::json!({
                    "generated": false,
                    "vulnerabilities": 0,
                }));
            }

            get_pdf(vulns.clone(), &report_name)?;
            get_excel(vulns.clone(), &report_name)?;
            get_html(vulns, &report_name)?;

            Ok(serde_json::json!({
                "generated": true,
                "vulnerabilities": count,
                "pdf_path": format!("{}.pdf", report_name),
                "xlsx_path": format!("{}.xlsx", report_name),
                "html_path": format!("{}.html", report_name),
            }))
        })
    })();

    make_response(result)
}
