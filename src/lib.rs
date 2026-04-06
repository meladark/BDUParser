use std::{ fs::{ self, File }, io::Write, process::{ Command, ExitStatus } };

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
            sec = Section::new(&now_sec);
            old_sec = now_sec;
        }
        sec.push(
            &*format!(
                "\\subsection{{\\href{{https://bdu.fstec.ru/vul/{}}}{{{}}}}}",
                &bug.vuln.id[4..],
                &bug.vuln.id
            )
        );
        if let Some(name_vuln) = bug.vuln.name_vuln {
            sec.push(
                &*format!("\\begin{{spverbatim}}Наименование: {}\\end{{spverbatim}}", &name_vuln)
            );
        }
        for version in &bug.vuln.versions {
            if version.name == bug.component.name {
                if let Some(only) = &version.only {
                    sec.push(&*format!("Уязвима только версия: {}", only));
                    continue;
                }
                let mut rec = "Уязвима".to_string();
                if let Some(from) = &version.from {
                    rec = format!("{} с версии {}", rec, from);
                }
                if let Some(to) = &version.to {
                    rec = format!("{} по версию {}", rec, to);
                }
                if version.inclusive {
                    rec = format!("{} включительно", rec);
                }
                sec.push(&*format!("{}", rec));
            }
        }
        if let Some(date) = bug.vuln.date {
            sec.push(&*format!("Дата обнаружения: {}", &date));
        }
        if let Some(severity) = bug.vuln.severity {
            sec.push(&*format!("Уровень опасности: {}", &severity));
        }
        if let Some(exploit) = bug.vuln.exploit {
            sec.push(&*format!("Наличие эксплойта: {}", &exploit));
        }
        if let Some(fix) = bug.vuln.fix {
            sec.push(&*format!("Информация об устранении: {}", &fix));
        }
        if let Some(desc_vuln) = bug.vuln.desc_vuln {
            sec.push(
                &*format!(
                    "\\begin{{spverbatim}}Описание уязвимости: {}\\end{{spverbatim}}",
                    &desc_vuln
                )
            );
        }
        if let Some(source_sites) = bug.vuln.source_sites {
            sec.push("Информационные сайты:");
            if source_sites.len() > 0 {
                sec.push("\\begin{enumerate}");
                for ss in source_sites {
                    sec.push(&*format!("\\item \\url{{{}}}", ss));
                }
                sec.push("\\end{enumerate}");
            } else {
                sec.push("Отстутствуют");
            }
        }
        if let Some(info) = bug.vuln.info {
            if info != "" {
                sec.push(
                    &*format!(
                        "\\begin{{spverbatim}}Дополнительная информация: {}\\end{{spverbatim}}",
                        &info
                    )
                );
            }
        }
    }
    doc.push(sec);
    let binding = latex::print(&doc).expect("print");
    let rendered = binding.as_bytes();
    let file_name = format!("{}.tex", name);
    let mut f = File::create(&file_name).expect("open");
    let _ = f.write_all(rendered).expect("writer");
    let exit_status = Command::new("pdflatex").arg(&file_name).status();
    match exit_status {
        Ok(es) => {
            let exit_status = Command::new("pdflatex").arg(&file_name).status();
            debug!("First pdflatex exit status for {}: {}", file_name, es);
            match exit_status {
                Ok(es) => {
                    // let _ = fs::remove_file(file_name);
                    let _ = fs::remove_file(format!("{}.log", name));
                    let _ = fs::remove_file(format!("{}.out", name));
                    let _ = fs::remove_file(format!("{}.toc", name));
                    let _ = fs::remove_file(format!("{}.aux", name));
                    let _ = fs::remove_file(format!("{}.fls", name));
                    let _ = fs::remove_file(format!("{}.fdb_latexmk", name));
                    if !ExitStatus::success(&es) {
                        error!("Second pdflatex execution failed for {}: {}", file_name, es);
                        return Err(format!("Код возврата неудачный: {}", es));
                    }
                }
                Err(e) => {
                    error!("Second pdflatex execution failed for {}: {}", file_name, e);
                    return Err(format!("Error second generate pdf: {}", e));
                }
            }
            if !ExitStatus::success(&es) {
                error!("First pdflatex execution failed for {}: {}", file_name, es);
                return Err(format!("Код возврата неудачный: {}", es));
            }
        }
        Err(e) => {
            error!("Failed to start first pdflatex execution for {}: {}", file_name, e);
            return Err(format!("Error first generate pdf: {}", e));
        }
    }
    info!("Generated PDF report {}.pdf", name);
    Ok(())
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
        worksheet
            .write_string(0, col as u16, *header)
            .map_err(|e| e.to_string())?;
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

    workbook.save(format!("{}.xlsx", name)).map_err(|e| e.to_string())?;
    info!("Generated Excel report {}.xlsx", name);
    Ok(())
}

pub fn new_get_pdf(_bugs: Vec<Bugs>) {}
