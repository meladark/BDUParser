use std::{ fs::{ self, File }, io::Write, process::{ Command, ExitStatus } };

use bd::Bugs;
use latex::{ Document, DocumentClass, Element, PreambleElement, Section };
use log::*;
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
        debug!("{} {}", &bug.component.name, &bug.vuln.id);
        let now_sec;
        if let Some(ver) = &bug.component.version {
            now_sec = format!("{}@{}", &bug.component.name, ver);
        } else {
            now_sec = bug.component.name;
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
            debug!("Latex first code exit: {}", es);
            match exit_status {
                Ok(es) => {
                    let _ = fs::remove_file(file_name);
                    let _ = fs::remove_file(format!("{}.log", name));
                    let _ = fs::remove_file(format!("{}.out", name));
                    let _ = fs::remove_file(format!("{}.toc", name));
                    let _ = fs::remove_file(format!("{}.aux", name));
                    if !ExitStatus::success(&es) {
                        error!("Неудачный код возврата second latex: {}", es);
                        return Err(format!("Код возврата неудачный: {}", es));
                    }
                }
                Err(e) => {
                    error!("Error second generate pdf: {}", e);
                    format!("Error second generate pdf: {}", e).to_string();
                }
            }
            if !ExitStatus::success(&es) {
                error!("Неудачный код возврата first latex: {}", es);
                return Err(format!("Код возврата неудачный: {}", es));
            }
        }
        Err(e) => {
            error!("Error first generate pdf: {}", e);
            format!("Error first generate pdf: {}", e).to_string();
        }
    }
    Ok(())
}
