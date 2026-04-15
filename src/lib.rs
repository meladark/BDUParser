use std::{collections::BTreeMap, fs, path::PathBuf};

use bd::Bugs;
use comemo::Prehashed;
use log::*;
use md5::Md5;
use rust_xlsxwriter::Workbook;
use sha2::{Digest, Sha256};
use streebog::Streebog256;
use typst::{
    Library, World,
    diag::{FileError, FileResult, SourceDiagnostic},
    eval::Tracer,
    foundations::{Bytes, Datetime, Smart},
    syntax::{FileId, Source, VirtualPath, package::PackageSpec},
    text::{Font, FontBook},
};
pub mod bd;
mod bdu;
mod sbom5;

#[cfg(test)]
mod test;

/// Сгенерировать ПДФ отчет по полученным багам от `self.find`.
///
/// # Arguments
/// * bugs - Список багов
/// * name - имя файла сборки
pub fn get_pdf(bugs: Vec<Bugs>, name: &String) -> Result<(), String> {
    let components = collect_components_from_bugs(&bugs);
    get_pdf_with_components(bugs, components, name)
}

/// Сгенерировать ПДФ отчет по полученным багам и полному списку компонентов SBOM.
pub fn get_pdf_with_components(
    bugs: Vec<Bugs>,
    components: Vec<sbom5::Component>,
    name: &String,
) -> Result<(), String> {
    get_pdf_with_components_and_source(bugs, components, None, name)
}

pub fn get_pdf_with_components_and_source(
    bugs: Vec<Bugs>,
    components: Vec<sbom5::Component>,
    source_path: Option<&str>,
    name: &String,
) -> Result<(), String> {
    info!(
        "Generating PDF report {}.pdf with {} vulnerabilities",
        name,
        bugs.len()
    );
    let source_hashes = source_path.map(hash_source_file).transpose()?;
    let report_source = build_typst_report(&bugs, &components, source_hashes.as_ref());
    let world = TypstReportWorld::new(report_source);
    let mut tracer = Tracer::new();
    let document = typst::compile(&world, &mut tracer).map_err(format_typst_diagnostics)?;

    for warning in tracer.warnings() {
        warn!("Typst warning: {}", warning.message);
    }

    let pdf = typst_pdf::pdf(&document, Smart::Auto, None);
    fs::write(format!("{}.pdf", name), pdf)
        .map_err(|e| format!("Failed to write PDF report {}.pdf: {}", name, e))?;
    info!("Generated PDF report {}.pdf", name);
    Ok(())
}

/// Сгенерировать HTML отчет по полученным багам от `self.find`.
///
/// # Arguments
/// * bugs - Список багов
/// * name - имя файла сборки
pub fn get_html(bugs: Vec<Bugs>, name: &String) -> Result<(), String> {
    info!(
        "Generating HTML report {}.html with {} vulnerabilities",
        name,
        bugs.len()
    );

    let mut html = String::from(
        "<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Отчет Карги</title>\n<style>\n:root{color-scheme:light dark;}body{margin:0;padding:24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f7fb;color:#1f2937;}main{max-width:1100px;margin:0 auto;}h1{margin-bottom:8px;}p.meta{margin-top:0;color:#4b5563;}section.component{background:#fff;border:1px solid #dbe3f0;border-radius:16px;padding:20px;margin:20px 0;box-shadow:0 8px 24px rgba(15,23,42,.06);}article.vuln{padding:16px 0;border-top:1px solid #e5e7eb;}article.vuln:first-of-type{border-top:none;padding-top:0;}dl{display:grid;grid-template-columns:minmax(180px,220px) 1fr;gap:8px 16px;margin:0 0 16px;}dt{font-weight:600;}dd{margin:0;}ul{margin:0;padding-left:20px;}p,li{line-height:1.55;}a{color:#0f62fe;text-decoration:none;}a:hover{text-decoration:underline;}div.block{margin:16px 0;}div.empty{color:#6b7280;font-style:italic;}@media (max-width:700px){body{padding:16px;}section.component{padding:16px;}dl{grid-template-columns:1fr;gap:4px 0;}}@media (prefers-color-scheme:dark){body{background:#0f172a;color:#e5e7eb;}p.meta{color:#94a3b8;}section.component{background:#111827;border-color:#334155;box-shadow:none;}article.vuln{border-color:#1f2937;}div.empty{color:#94a3b8;}a{color:#7dd3fc;}}\n</style>\n</head>\n<body>\n<main>\n",
    );
    html.push_str("<h1>Отчет Карги</h1>\n");
    html.push_str(&format!(
        "<p class=\"meta\">BDUParser v{} • Найдено уязвимостей: {}</p>\n",
        env!("CARGO_PKG_VERSION"),
        bugs.len()
    ));

    let mut old_component = String::new();
    let mut open_section = false;

    for bug in bugs {
        let component_name = format_component_name(&bug);
        if component_name != old_component {
            if open_section {
                html.push_str("</section>\n");
            }
            html.push_str(&format!(
                "<section class=\"component\">\n<h2>{}</h2>\n",
                escape_html(&component_name)
            ));
            old_component = component_name;
            open_section = true;
        }

        let vuln_link = if bug.vuln.id.len() > 4 {
            format!("https://bdu.fstec.ru/vul/{}", &bug.vuln.id[4..])
        } else {
            "https://bdu.fstec.ru/vul".to_string()
        };
        let vulnerable_versions = format_vulnerable_versions(&bug, escape_html);

        html.push_str("<article class=\"vuln\">\n");
        html.push_str(&format!(
            "<h3><a href=\"{}\" target=\"_blank\" rel=\"noreferrer\">{}</a></h3>\n",
            escape_html_attr(&vuln_link),
            escape_html(&bug.vuln.id)
        ));
        html.push_str("<dl>\n");

        if let Some(name_vuln) = &bug.vuln.name_vuln {
            push_html_field(&mut html, "Наименование", escape_html(name_vuln));
        }
        if !vulnerable_versions.is_empty() {
            let items = vulnerable_versions
                .into_iter()
                .map(|item| format!("<li>{}</li>", item))
                .collect::<Vec<String>>()
                .join("");
            push_html_field(
                &mut html,
                "Затронутые версии",
                format!("<ul>{}</ul>", items),
            );
        }
        if let Some(date) = &bug.vuln.date {
            push_html_field(&mut html, "Дата обнаружения", escape_html(date));
        }
        if let Some(severity) = &bug.vuln.severity {
            push_html_field(&mut html, "Уровень опасности", escape_html(severity));
        }
        if let Some(exploit) = &bug.vuln.exploit {
            push_html_field(&mut html, "Наличие эксплойта", escape_html(exploit));
        }
        if let Some(fix) = &bug.vuln.fix {
            push_html_field(&mut html, "Устранение", escape_html(fix));
        }

        html.push_str("</dl>\n");

        if let Some(desc_vuln) = &bug.vuln.desc_vuln {
            html.push_str(&format!(
                "<div class=\"block\"><h4>Описание уязвимости</h4><p>{}</p></div>\n",
                html_multiline(desc_vuln)
            ));
        }

        if let Some(source_sites) = &bug.vuln.source_sites {
            html.push_str("<div class=\"block\"><h4>Источники</h4>");
            if source_sites.is_empty() {
                html.push_str("<div class=\"empty\">Отсутствуют</div>");
            } else {
                let items = source_sites
                    .iter()
                    .map(|site| {
                        format!(
                            "<li><a href=\"{}\" target=\"_blank\" rel=\"noreferrer\">{}</a></li>",
                            escape_html_attr(site.trim()),
                            escape_html(site.trim())
                        )
                    })
                    .collect::<Vec<String>>()
                    .join("");
                html.push_str(&format!("<ul>{}</ul>", items));
            }
            html.push_str("</div>\n");
        }

        if let Some(info) = &bug.vuln.info {
            if !info.is_empty() {
                html.push_str(&format!(
                    "<div class=\"block\"><h4>Дополнительная информация</h4><p>{}</p></div>\n",
                    html_multiline(info)
                ));
            }
        }

        html.push_str("</article>\n");
    }

    if open_section {
        html.push_str("</section>\n");
    } else {
        html.push_str(
            "<section class=\"component\"><p class=\"meta\">Уязвимости не найдены.</p></section>\n",
        );
    }

    html.push_str("</main>\n</body>\n</html>\n");

    fs::write(format!("{}.html", name), html)
        .map_err(|e| format!("Failed to write HTML report {}.html: {}", name, e))?;
    info!("Generated HTML report {}.html", name);
    Ok(())
}

struct TypstReportWorld {
    library: Prehashed<Library>,
    book: Prehashed<FontBook>,
    fonts: Vec<Font>,
    main: Source,
}

impl TypstReportWorld {
    fn new(main_source: String) -> Self {
        let fonts = typst_assets::fonts()
            .flat_map(|font_bytes| Font::iter(Bytes::from_static(font_bytes)))
            .collect::<Vec<Font>>();
        let book = FontBook::from_fonts(fonts.iter());

        Self {
            library: Prehashed::new(Library::default()),
            book: Prehashed::new(book),
            fonts,
            main: Source::new(
                FileId::new(None, VirtualPath::new("/report.typ")),
                main_source,
            ),
        }
    }
}

impl World for TypstReportWorld {
    fn library(&self) -> &Prehashed<Library> {
        &self.library
    }

    fn book(&self) -> &Prehashed<FontBook> {
        &self.book
    }

    fn main(&self) -> Source {
        self.main.clone()
    }

    fn source(&self, id: FileId) -> FileResult<Source> {
        if id == self.main.id() {
            Ok(self.main.clone())
        } else {
            Err(FileError::NotFound(PathBuf::from(
                id.vpath().as_rooted_path(),
            )))
        }
    }

    fn file(&self, id: FileId) -> FileResult<Bytes> {
        Err(FileError::NotFound(PathBuf::from(
            id.vpath().as_rooted_path(),
        )))
    }

    fn font(&self, index: usize) -> Option<Font> {
        self.fonts.get(index).cloned()
    }

    fn today(&self, _offset: Option<i64>) -> Option<Datetime> {
        None
    }

    fn packages(&self) -> &[(PackageSpec, Option<typst::diag::EcoString>)] {
        &[]
    }
}

struct ReportSourceHashes {
    md5: String,
    sha256: String,
    streebog256: String,
}

fn hash_source_file(source_path: &str) -> Result<ReportSourceHashes, String> {
    let bytes = fs::read(source_path)
        .map_err(|e| format!("Failed to read source file {} for hashing: {}", source_path, e))?;

    Ok(ReportSourceHashes {
        md5: hex::encode(Md5::digest(&bytes)),
        sha256: hex::encode(Sha256::digest(&bytes)),
        streebog256: hex::encode(Streebog256::digest(&bytes)),
    })
}

fn build_typst_report(
    bugs: &[Bugs],
    components: &[sbom5::Component],
    source_hashes: Option<&ReportSourceHashes>,
) -> String {
    let mut report = String::from(
        "#set page(paper: \"a4\", margin: (x: 18mm, y: 18mm))\n#set document(title: \"Отчет Карги\", author: (\"BDUParser\",))\n#set text(lang: \"ru\", font: \"Linux Libertine O\", size: 10pt)\n#set par(justify: true, leading: 0.75em)\n#set heading(numbering: \"1.1.1\")\n#show heading.where(level: 1): set text(size: 18pt, weight: \"bold\")\n#show heading.where(level: 2): set text(size: 16pt, weight: \"bold\")\n#show heading.where(level: 3): set text(size: 13pt, weight: \"bold\")\n\n#v(35%)\n#align(center)[\n  #text(size: 24pt, weight: \"bold\")[Отчет Карги]\n\n",
    );
    report.push_str(&format!(
        "  #text(size: 12pt)[BDUParser v{}]\n\n  #text(size: 11pt, fill: rgb(102, 102, 102))[Найдено уязвимостей: {}]\n\n",
        env!("CARGO_PKG_VERSION"),
        bugs.len()
    ));
    if let Some(source_hashes) = source_hashes {
        report.push_str(&format!(
            "  #text(size: 9pt, fill: rgb(102, 102, 102))[MD5: {}]\n\n  #text(size: 9pt, fill: rgb(102, 102, 102))[SHA-256: {}]\n\n  #text(size: 9pt, fill: rgb(102, 102, 102))[Streebog-256: {}]\n",
            source_hashes.md5,
            source_hashes.sha256,
            source_hashes.streebog256
        ));
    }
    report.push_str("]\n\n#pagebreak()\n\n#align(center)[#text(size: 20pt, weight: \"bold\")[Содержание]]\n\n#outline()\n\n#pagebreak()\n\n");
    report.push_str(&build_typst_summary_table(bugs, components));
    report.push_str("= Уязвимости\n\n");

    let mut old_component = String::new();
    for bug in bugs {
        let component_name = format_component_name(bug);
        if component_name != old_component {
            report.push_str(&format!("== {}\n\n", typst_inline_text(&component_name)));
            old_component = component_name;
        }

        let vuln_link = bdu_vulnerability_url(&bug.vuln.id);
        report.push_str(&format!(
            "=== #link({})[{}]\n\n",
            typst_string_literal(&vuln_link),
            typst_inline_text(&bug.vuln.id)
        ));

        if let Some(name_vuln) = &bug.vuln.name_vuln {
            report.push_str(&typst_field_line("Наименование", name_vuln));
        }

        let vulnerable_versions = format_vulnerable_versions(bug, |value| value.to_string());
        if !vulnerable_versions.is_empty() {
            report.push_str("*Затронутые версии:*\n");
            for item in vulnerable_versions {
                report.push_str(&format!("- {}\n", typst_inline_text(&item)));
            }
            report.push('\n');
        }

        if let Some(date) = &bug.vuln.date {
            report.push_str(&typst_field_line("Дата обнаружения", date));
        }
        if let Some(severity) = &bug.vuln.severity {
            report.push_str(&typst_field_line("Уровень опасности", severity));
        }
        if let Some(exploit) = &bug.vuln.exploit {
            report.push_str(&typst_field_line("Наличие эксплойта", exploit));
        }
        if let Some(fix) = &bug.vuln.fix {
            report.push_str(&typst_field_line("Устранение", fix));
        }

        if let Some(desc_vuln) = &bug.vuln.desc_vuln {
            report.push_str(&typst_block("Описание уязвимости", desc_vuln));
        }

        if let Some(source_sites) = &bug.vuln.source_sites {
            report.push_str("*Источники:*\n");
            if source_sites.is_empty() {
                report.push_str("- Отсутствуют\n\n");
            } else {
                for site in source_sites {
                    let trimmed = site.trim();
                    report.push_str(&format!(
                        "- #link({})[{}]\n",
                        typst_string_literal(trimmed),
                        typst_inline_text(trimmed)
                    ));
                }
                report.push('\n');
            }
        }

        if let Some(info) = &bug.vuln.info {
            if !info.is_empty() {
                report.push_str(&typst_block("Дополнительная информация", info));
            }
        }

        report.push_str("#v(1.2em)\n\n");
    }

    if bugs.is_empty() {
        report.push_str("Уязвимости не найдены.\n");
    }

    report
}

fn build_typst_summary_table(bugs: &[Bugs], components: &[sbom5::Component]) -> String {
    let mut rows = BTreeMap::new();
    for component in components {
        rows.entry(format_component(component))
            .or_insert_with(SeveritySummary::default);
    }

    for bug in bugs {
        rows.entry(format_component(&bug.component))
            .or_insert_with(SeveritySummary::default)
            .increment(bug.vuln.severity.as_deref());
    }

    let mut summary = String::from("= Сводка по критичности\n\n");
    summary.push_str(
        "#table(\n  columns: (auto, auto, auto, auto, auto),\n  inset: 6pt,\n  stroke: 0.4pt,\n  align: (left, center, center, center, center),\n  table.header(\n    [*Пакет*], [*Критический*], [*Высокий*], [*Средний*], [*Низкий*],\n  ),\n",
    );

    let mut rows = rows.into_iter().collect::<Vec<(String, SeveritySummary)>>();
    rows.sort_by(|(left_name, _), (right_name, _)| {
        left_name
            .to_lowercase()
            .cmp(&right_name.to_lowercase())
            .then_with(|| left_name.cmp(right_name))
    });

    if rows.is_empty() {
        summary.push_str("  [Компоненты не найдены], table.cell(colspan: 4, align: center)[Не выявлено],\n");
    } else {
        for (component, counts) in rows {
            if counts.is_empty() {
                summary.push_str(&format!(
                    "  [{}], table.cell(colspan: 4, align: center)[Не выявлено],\n",
                    typst_inline_text(&component)
                ));
            } else {
                summary.push_str(&format!(
                    "  [{}], [{}], [{}], [{}], [{}],\n",
                    typst_inline_text(&component),
                    counts.critical,
                    counts.high,
                    counts.medium,
                    counts.low
                ));
            }
        }
    }

    summary.push_str(")\n\n");
    summary
}

fn typst_field_line(label: &str, value: &str) -> String {
    format!(
        "*{}:* {}\n\n",
        typst_inline_text(label),
        typst_inline_text(value)
    )
}

fn typst_block(title: &str, value: &str) -> String {
    let mut block = format!("*{}:*\n\n", typst_inline_text(title));
    for line in value.lines() {
        if line.trim().is_empty() {
            block.push('\n');
        } else {
            block.push_str(&format!("{}\n", typst_inline_text(line)));
        }
    }
    block.push('\n');
    block
}

fn typst_inline_text(input: &str) -> String {
    format!("#({})", typst_string_literal(input))
}

fn typst_string_literal(input: &str) -> String {
    input.chars().fold(String::from("\""), |mut acc, ch| {
        match ch {
            '\\' => acc.push_str("\\\\"),
            '"' => acc.push_str("\\\""),
            '\n' => acc.push_str("\\n"),
            '\r' => acc.push_str("\\r"),
            '\t' => acc.push_str("\\t"),
            _ => acc.push(ch),
        }
        acc
    }) + "\""
}

fn format_typst_diagnostics<I>(errors: I) -> String
where
    I: IntoIterator<Item = SourceDiagnostic>,
{
    errors
        .into_iter()
        .map(|error| {
            if error.hints.is_empty() {
                error.message.to_string()
            } else {
                format!(
                    "{} ({})",
                    error.message,
                    error
                        .hints
                        .iter()
                        .map(|hint| hint.as_str())
                        .collect::<Vec<&str>>()
                        .join("; ")
                )
            }
        })
        .collect::<Vec<String>>()
        .join("\n")
}

fn escape_html(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            _ => ch.to_string(),
        })
        .collect()
}

fn escape_html_attr(input: &str) -> String {
    escape_html(input)
}

fn html_multiline(input: &str) -> String {
    escape_html(input).replace('\n', "<br>\n")
}

fn push_html_field(html: &mut String, label: &str, value: String) {
    html.push_str(&format!(
        "<dt>{}</dt><dd>{}</dd>\n",
        escape_html(label),
        value
    ));
}

fn bdu_vulnerability_url(vuln_id: &str) -> String {
    if vuln_id.len() > 4 {
        format!("https://bdu.fstec.ru/vul/{}", &vuln_id[4..])
    } else {
        "https://bdu.fstec.ru/vul".to_string()
    }
}

fn format_component_name(bug: &Bugs) -> String {
    format_component(&bug.component)
}

fn format_component(component: &sbom5::Component) -> String {
    match &component.version {
        Some(version) => format!("{}@{}", component.name, version),
        None => component.name.clone(),
    }
}

fn collect_components_from_bugs(bugs: &[Bugs]) -> Vec<sbom5::Component> {
    let mut components = BTreeMap::new();
    for bug in bugs {
        components
            .entry(format_component(&bug.component))
            .or_insert_with(|| bug.component.clone());
    }
    components.into_values().collect()
}

#[derive(Default)]
struct SeveritySummary {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

impl SeveritySummary {
    fn increment(&mut self, severity: Option<&str>) {
        match normalize_severity(severity) {
            SeverityKind::Critical => self.critical += 1,
            SeverityKind::High => self.high += 1,
            SeverityKind::Medium => self.medium += 1,
            SeverityKind::Low => self.low += 1,
            SeverityKind::Unknown => {}
        }
    }

    fn is_empty(&self) -> bool {
        self.critical == 0 && self.high == 0 && self.medium == 0 && self.low == 0
    }
}

enum SeverityKind {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

fn normalize_severity(severity: Option<&str>) -> SeverityKind {
    let normalized = severity.unwrap_or("").trim().to_lowercase();
    if normalized.starts_with("крит") {
        SeverityKind::Critical
    } else if normalized.starts_with("выс") {
        SeverityKind::High
    } else if normalized.starts_with("сред") {
        SeverityKind::Medium
    } else if normalized.starts_with("низ") {
        SeverityKind::Low
    } else {
        SeverityKind::Unknown
    }
}

fn format_vulnerable_versions<F>(bug: &Bugs, escape: F) -> Vec<String>
where
    F: Fn(&str) -> String,
{
    bug.vuln
        .versions
        .iter()
        .filter(|version| version.name == bug.component.name)
        .map(|version| {
            if let Some(only) = &version.only {
                return format!("Уязвима только версия {}", escape(only));
            }

            let mut record = "Уязвима".to_string();
            if let Some(from) = &version.from {
                record = format!("{} с версии {}", record, escape(from));
            }
            if let Some(to) = &version.to {
                record = format!("{} по версию {}", record, escape(to));
            }
            if version.inclusive {
                record = format!("{} включительно", record);
            }
            record
        })
        .collect()
}

/// Сгенерировать Excel отчет по полученным багам от `self.find`.
///
/// # Arguments
/// * bugs - Список багов
/// * name - имя файла сборки
pub fn get_excel(bugs: Vec<Bugs>, name: &String) -> Result<(), String> {
    info!(
        "Generating Excel report {}.xlsx with {} vulnerabilities",
        name,
        bugs.len()
    );
    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();

    worksheet.set_name("Report").map_err(|e| e.to_string())?;

    let headers = [
        "Компонент",
        "Версия компонента",
        "Идентификатор уязвимости",
        "Наименование уязвимости",
        "Уязвимые версии",
        "Дата обнаружения",
        "Уровень опасности",
        "Наличие эксплойта",
        "Информация об устранении",
        "Описание уязвимости",
        "Информационные сайты",
        "Дополнительная информация",
    ];

    for (col, header) in headers.iter().enumerate() {
        worksheet
            .write_string(0, col as u16, *header)
            .map_err(|e| e.to_string())?;
    }

    for (idx, bug) in bugs.iter().enumerate() {
        let row = (idx + 1) as u32;
        let vulnerable_versions =
            format_vulnerable_versions(bug, |value| value.to_string()).join("; ");
        let source_sites = bug.vuln.source_sites.clone().unwrap_or_default().join("\n");

        worksheet
            .write_string(row, 0, &bug.component.name)
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 1, bug.component.version.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 2, &bug.vuln.id)
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 3, bug.vuln.name_vuln.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 4, &vulnerable_versions)
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 5, bug.vuln.date.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 6, bug.vuln.severity.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 7, bug.vuln.exploit.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 8, bug.vuln.fix.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 9, bug.vuln.desc_vuln.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 10, &source_sites)
            .map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 11, bug.vuln.info.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
    }

    workbook
        .save(format!("{}.xlsx", name))
        .map_err(|e| e.to_string())?;
    info!("Generated Excel report {}.xlsx", name);
    Ok(())
}

pub fn new_get_pdf(_bugs: Vec<Bugs>) {}
