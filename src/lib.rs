use std::{ fs::{ self, File }, io::Write, path::Path, process::{ Command, ExitStatus } };

use bd::Bugs;
use latex::{ Document, DocumentClass, Element, PreambleElement, Section };
use log::*;
use rust_xlsxwriter::Workbook;
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
    info!("Generating PDF report {}.pdf with {} vulnerabilities", name, bugs.len());
    let report_path = Path::new(name);
    let output_dir = report_path.parent().unwrap_or_else(|| Path::new("."));
    let base_name = report_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("Invalid report path: {}", name))?
        .to_string();

    let mut doc = Document::new(DocumentClass::Article);
    doc.preamble
        .push(PreambleElement::UsePackage {
            package: "inputenc".to_string(),
            argument: Some("utf8".to_string()),
        })
        .push(PreambleElement::UsePackage {
            package: "fontenc".to_string(),
            argument: Some("T2A".to_string()),
        })
        .push(PreambleElement::UsePackage {
            package: "babel".to_string(),
            argument: Some("english,russian".to_string()),
        })
        .title("Отчет Карги")
        .author(&*format!("BDUParser v{}", env!("CARGO_PKG_VERSION")))
        .use_package("amsmath")
        .use_package("hyperref")
        .use_package("spverbatim");
    doc.push(Element::TitlePage);
    doc.push(Element::ClearPage);
    doc.push(Element::TableOfContents);
    doc.push(Element::ClearPage);
    let mut old_sec = "".to_string();
    let mut sec = Section::new(&old_sec);
    for bug in bugs {
        let now_sec;
        if let Some(ver) = &bug.component.version {
            now_sec = format!("{}@{}", &bug.component.name, ver);
        } else {
            now_sec = bug.component.name.clone();
        }
        if now_sec != old_sec {
            if old_sec != "".to_string() {
                doc.push(sec);
            }
            sec = Section::new(&escape_latex(&now_sec));
            old_sec = now_sec;
        }
        sec.push(
            &*format!(
                "\\subsection{{\\href{{https://bdu.fstec.ru/vul/{}}}{{{}}}}}",
                &bug.vuln.id[4..],
                escape_latex(&bug.vuln.id)
            )
        );
        sec.push("\\begin{description}[leftmargin=3.8cm,style=nextline,font=\\normalfont\\bfseries]");
        if let Some(name_vuln) = bug.vuln.name_vuln {
            sec.push(&*format!("\\item[Наименование] {}", escape_latex(&name_vuln)));
        }

        let vulnerable_versions = bug.vuln.versions
            .iter()
            .filter(|version| version.name == bug.component.name)
            .map(|version| {
                if let Some(only) = &version.only {
                    return format!("Уязвима только версия {}", escape_latex(only));
                }

                let mut rec = "Уязвима".to_string();
                if let Some(from) = &version.from {
                    rec = format!("{} с версии {}", rec, escape_latex(from));
                }
                if let Some(to) = &version.to {
                    rec = format!("{} по версию {}", rec, escape_latex(to));
                }
                if version.inclusive {
                    rec = format!("{} включительно", rec);
                }
                rec
            })
            .collect::<Vec<String>>();

        if !vulnerable_versions.is_empty() {
            sec.push("\\item[Затронутые версии] ");
            sec.push("\\begin{itemize}[leftmargin=*,nosep]");
            for rec in vulnerable_versions {
                sec.push(&*format!("\\item {}", rec));
            }
            sec.push("\\end{itemize}");
        }

        if let Some(date) = bug.vuln.date {
            sec.push(&*format!("\\item[Дата обнаружения] {}", escape_latex(&date)));
        }
        if let Some(severity) = bug.vuln.severity {
            sec.push(&*format!("\\item[Уровень опасности] {}", escape_latex(&severity)));
        }
        if let Some(exploit) = bug.vuln.exploit {
            sec.push(&*format!("\\item[Наличие эксплойта] {}", escape_latex(&exploit)));
        }
        if let Some(fix) = bug.vuln.fix {
            sec.push(&*format!("\\item[Устранение] {}", escape_latex(&fix)));
        }
        sec.push("\\end{description}");

        if let Some(desc_vuln) = bug.vuln.desc_vuln {
            sec.push("\\medskip\\noindent\\textbf{Описание уязвимости}\\par");
            sec.push(&*escape_latex(&desc_vuln));
        }

        if let Some(source_sites) = bug.vuln.source_sites {
            if !source_sites.is_empty() {
                sec.push("\\medskip\\noindent\\textbf{Источники}\\par");
                sec.push("\\begin{itemize}[leftmargin=*,nosep]");
                for ss in source_sites {
                    sec.push(&*format!("\\item \\url{{{}}}", latex_safe_url(ss.trim())));
                }
                sec.push("\\end{itemize}");
            } else {
                sec.push("\\medskip\\noindent\\textbf{Источники}\\par");
                sec.push("Отсутствуют");
            }
        }
        if let Some(info) = bug.vuln.info {
            if info != "" {
                sec.push("\\medskip\\noindent\\textbf{Дополнительная информация}\\par");
                sec.push(&*escape_latex(&info));
            }
        }
        sec.push("\\bigskip");
    }
    doc.push(sec);
    let binding = latex
        ::print(&doc)
        .map_err(|e| format!("Failed to render LaTeX document: {}", e))?;
    let rendered = patch_latex_preamble(&binding);
    let file_name = format!("{}.tex", name);
    let mut f = File::create(&file_name).map_err(|e|
        format!("Failed to create LaTeX source {}: {}", file_name, e)
    )?;
    f
        .write_all(rendered.as_bytes())
        .map_err(|e| format!("Failed to write LaTeX source {}: {}", file_name, e))?;
    let latex_engine = latex_engine();
    let exit_status = run_latex(&latex_engine, output_dir, &file_name);
    match exit_status {
        Ok(es) => {
            let exit_status = run_latex(&latex_engine, output_dir, &file_name);
            debug!("First {} exit status for {}: {}", latex_engine, file_name, es);
            match exit_status {
                Ok(es) => {
                    // let _ = fs::remove_file(file_name);
                    let _ = fs::remove_file(output_dir.join(format!("{}.log", base_name)));
                    let _ = fs::remove_file(output_dir.join(format!("{}.out", base_name)));
                    let _ = fs::remove_file(output_dir.join(format!("{}.toc", base_name)));
                    let _ = fs::remove_file(output_dir.join(format!("{}.aux", base_name)));
                    let _ = fs::remove_file(output_dir.join(format!("{}.fls", base_name)));
                    let _ = fs::remove_file(output_dir.join(format!("{}.fdb_latexmk", base_name)));
                    if !ExitStatus::success(&es) {
                        error!("Second {} execution failed for {}: {}", latex_engine, file_name, es);
                        return Err(format!("Код возврата неудачный: {}", es));
                    }
                }
                Err(e) => {
                    error!("Second {} execution failed for {}: {}", latex_engine, file_name, e);
                    return Err(format!("Error second generate pdf: {}", e));
                }
            }
            if !ExitStatus::success(&es) {
                error!("First {} execution failed for {}: {}", latex_engine, file_name, es);
                return Err(format!("Код возврата неудачный: {}", es));
            }
        }
        Err(e) => {
            error!("Failed to start first {} execution for {}: {}", latex_engine, file_name, e);
            return Err(format!("Error first generate pdf: {}", e));
        }
    }
    info!("Generated PDF report {}.pdf", name);
    Ok(())
}

fn patch_latex_preamble(rendered: &str) -> String {
    rendered.replace(
        "\\usepackage[utf8]{inputenc}\n\\usepackage[T2A]{fontenc}\n\\usepackage[english,russian]{babel}\n\\usepackage{amsmath}\n\\usepackage{hyperref}\n\\usepackage{spverbatim}\n",
        "\\usepackage{iftex}\n\\ifPDFTeX\n\\usepackage[utf8]{inputenc}\n\\usepackage[T2A]{fontenc}\n\\usepackage[english,russian]{babel}\n\\else\n\\usepackage{fontspec}\n\\usepackage{polyglossia}\n\\setmainlanguage{russian}\n\\setotherlanguage{english}\n\\setmainfont{Times New Roman}\n\\setsansfont{Arial}\n\\setmonofont{Arial}\n\\fi\n\\usepackage[a4paper,margin=1in]{geometry}\n\\usepackage{enumitem}\n\\usepackage{xurl}\n\\usepackage{amsmath}\n\\usepackage{hyperref}\n\\usepackage{spverbatim}\n\\hypersetup{hidelinks}\n\\setlength{\\parindent}{0pt}\n\\setlength{\\parskip}{0.5em}\n"
    )
}

fn latex_engine() -> &'static str {
    if Command::new("xelatex").arg("--version").output().is_ok() {
        "xelatex"
    } else {
        "pdflatex"
    }
}

fn run_latex(engine: &str, output_dir: &Path, file_name: &str) -> std::io::Result<ExitStatus> {
    Command::new(engine)
        .arg("-interaction=nonstopmode")
        .arg("-halt-on-error")
        .arg("-output-directory")
        .arg(output_dir)
        .arg(file_name)
        .status()
}

fn escape_latex(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            '\\' => "\\textbackslash{}".to_string(),
            '{' => "\\{".to_string(),
            '}' => "\\}".to_string(),
            '#' => "\\#".to_string(),
            '$' => "\\$".to_string(),
            '%' => "\\%".to_string(),
            '&' => "\\&".to_string(),
            '_' => "\\_".to_string(),
            '~' => "\\textasciitilde{}".to_string(),
            '^' => "\\textasciicircum{}".to_string(),
            '\n' => "\\\\\n".to_string(),
            _ => ch.to_string(),
        })
        .collect()
}

fn latex_safe_url(input: &str) -> String {
    input
        .trim()
        .replace('\\', "%5C")
        .replace('{', "%7B")
        .replace('}', "%7D")
}

/// Сгенерировать Excel отчет по полученным багам от `self.find`.
///
/// # Arguments
/// * bugs - Список багов
/// * name - имя файла сборки
pub fn get_excel(bugs: Vec<Bugs>, name: &String) -> Result<(), String> {
    info!("Generating Excel report {}.xlsx with {} vulnerabilities", name, bugs.len());
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
        worksheet.write_string(0, col as u16, *header).map_err(|e| e.to_string())?;
    }

    for (idx, bug) in bugs.iter().enumerate() {
        let row = (idx + 1) as u32;
        let vulnerable_versions = bug.vuln.versions
            .iter()
            .filter(|version| version.name == bug.component.name)
            .map(|version| {
                if let Some(only) = &version.only {
                    return format!("Только {}", only);
                }

                let mut record = String::from("Уязвима");
                if let Some(from) = &version.from {
                    record = format!("{} с версии {}", record, from);
                }
                if let Some(to) = &version.to {
                    record = format!("{} по версию {}", record, to);
                }
                if version.inclusive {
                    record = format!("{} включительно", record);
                }
                record
            })
            .collect::<Vec<String>>()
            .join("; ");
        let source_sites = bug.vuln.source_sites.clone().unwrap_or_default().join("\n");

        worksheet.write_string(row, 0, &bug.component.name).map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 1, bug.component.version.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        worksheet.write_string(row, 2, &bug.vuln.id).map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 3, bug.vuln.name_vuln.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        worksheet.write_string(row, 4, &vulnerable_versions).map_err(|e| e.to_string())?;
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
        worksheet.write_string(row, 10, &source_sites).map_err(|e| e.to_string())?;
        worksheet
            .write_string(row, 11, bug.vuln.info.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
    }

    workbook.save(format!("{}.xlsx", name)).map_err(|e| e.to_string())?;
    info!("Generated Excel report {}.xlsx", name);
    Ok(())
}

pub fn new_get_pdf(_bugs: Vec<Bugs>) {}
