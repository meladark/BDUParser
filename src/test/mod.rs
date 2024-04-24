#[cfg(test)]
mod test {
    use std::time::Instant;
    use env_logger;
    use log::{ self, warn, info };
    use crate::bd::BD;
    use std::fs::{ self, File };
    use std::io::Write;
    use std::process::Command;

    #[tokio::test]
    async fn test_postgres() {
        env_logger::init();
        // info!("Start test_postgres!!!!!");
        let t = BD::default().await.expect("Error default");
        let k = t.update().await;
        match k {
            Ok(_) => println!("Well done"),
            Err(err) => println!("{}", err),
        }
    }
    #[tokio::test]
    async fn test_find_bug_bd_one_query() {
        env_logger::init();
        info!("Start test_find_bug_bd_one_query!!!!!");
        let start = Instant::now();
        let t = BD::default().await.expect("Error connect");

        match t.find(&"extra/bom.1.5.json".to_string(), false).await {
            Ok(k) =>
                for i in k {
                    println!("{} {}", i.component.name, i.vuln.id);
                }
            Err(err) => println!("[Error] {}", err),
        }
        let duration = start.elapsed();
        println!("Time elapsed in find_bug_bd_one_query() is: {:?}", duration);
    }
    use latex::{ Align, Document, DocumentClass, Element, PreambleElement, Section };

    #[tokio::test]
    async fn test_latex() {
        let mut doc = Document::new(DocumentClass::Article);
        doc.preamble.push(PreambleElement::UsePackage {
            package: "inputenc".to_string(),
            argument: Some("utf8".to_string()),
        });
        doc.preamble.push(PreambleElement::UsePackage {
            package: "fontenc".to_string(),
            argument: Some("T2A".to_string()),
        });
        doc.preamble.push(PreambleElement::UsePackage {
            package: "babel".to_string(),
            argument: Some("english,russian".to_string()),
        });
        // Set some metadata for the document
        doc.preamble.title("My Fancy Document");
        doc.preamble.author("Russian/Русский");
        doc.preamble.use_package("amsmath");
        doc.preamble.use_package("hyperref");
        doc.push(Element::TitlePage)
            .push(Element::ClearPage)
            .push(Element::TableOfContents)
            .push(Element::ClearPage);

        let t = BD::default().await.expect("Error connect");

        match t.find(&"extra/bom.1.5.json".to_string(), true).await {
            Ok(k) => {
                let mut old_sec = "".to_string();
                let mut sec = Section::new(&old_sec);
                for i in k {
                    println!("{} {}", &i.component.name, &i.vuln.id);
                    let now_sec;
                    if let Some(ver) = &i.component.version {
                        now_sec = format!("{}@{}", &i.component.name, ver);
                    } else {
                        now_sec = i.component.name;
                    }
                    if now_sec != old_sec {
                        if old_sec != "".to_string() {
                            doc.push(sec);
                        }
                        sec = Section::new(&now_sec);
                        old_sec = now_sec;
                    }
                    // sec.push(Element::Input(()));
                    sec.push(
                        &*format!(
                            "Уязвимость: \\href{{https://bdu.fstec.ru/vul/{}}}{{{}}}",
                            &i.vuln.id[4..],
                            &i.vuln.id
                        )
                    );
                    if let Some(name_vuln) = i.vuln.name_vuln {
                        sec.push(&*format!("Описание: {}", &name_vuln));
                    }
                }
                doc.push(sec);
            }
            Err(err) => println!("[Error] {}", err),
        }
        let mut section_1 = Section::new("Section 1");
        section_1
            .push("Here is some text which will be put in paragraph 1.")
            .push("And here is some more text for paragraph 2.");
        doc.push(section_1);

        let mut section_2 = Section::new("Section 2");

        section_2.push("More text...").push(Align::from("y &= mx + c"));

        doc.push(section_2);

        let binding = latex::print(&doc).expect("print");
        let rendered = binding.as_bytes();
        let mut f = File::create("report.tex").expect("open");
        // print!("{}", &rendered);
        let _ = f.write_all(rendered).expect("writer");
        //write!(f, "{}", rendered).expect("write");

        // Then call latexmk on it
        let _exit_status = Command::new("pdflatex").arg("report.tex").status().expect("new");
    }
}
