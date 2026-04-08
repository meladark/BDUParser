#[cfg(test)]
mod test {
    use crate::{ bd::{ BD, Bugs }, bdu, get_excel, get_pdf, sbom5 };
    use calamine::{ Reader, Xlsx, open_workbook };
    use env_logger;
    use log::info;
    use std::fs;
    use std::time::Instant;

    #[tokio::test]
    async fn test_postgres() {
        env_logger::init();
        info!("Start test_postgres!!!!!");
        //let t = BD::default().await.expect("Error default");
        let t = BD::new(&"postgresql://bdu:bdu@localhost:5438/bdu".to_string()).await.expect(
            "Error New"
        );
        info!("Start updating DataBase.");
        match t.update().await {
            Ok(_) => println!("Well done"),
            Err(err) => println!("{}", err),
        }
    }
    #[tokio::test]
    async fn test_find_bug_bd_one_query() {
        env_logger::init();
        info!("Start test_find_bug_bd_one_query!!!!!");
        let start = Instant::now();
        // let t = BD::default().await.expect("Error connect");
        let t = BD::new(&"postgresql://bdu:bdu@localhost:5438/bdu".to_string()).await.expect(
            "Error New"
        );
        match t.find(&"extra/cleaned_data.json".to_string(), false).await {
            Ok(k) => {
                for i in k {
                    println!(
                        "{}@{} {}",
                        i.component.name,
                        match i.component.version {
                            Some(v) => v,
                            None => { "None".to_string() }
                        },
                        i.vuln.id
                    );
                }
            }
            Err(err) => println!("[Error] {}", err),
        }
        let duration = start.elapsed();
        println!("Time elapsed in find_bug_bd_one_query() is: {:?}", duration);
    }

    #[tokio::test]
    async fn test_no_valid() {
        env_logger::init();
        info!("Start no valid json!!!!!");
        let start = Instant::now();
        // let t = BD::default().await.expect("Error connect");
        let t = BD::new(&"postgresql://bdu:bdu@localhost:5438/bdu".to_string()).await.expect(
            "Error New"
        );
        match t.find(&"extra/no_valid.json".to_string(), false).await {
            Ok(k) => {
                for i in k {
                    println!(
                        "{}@{} {}",
                        i.component.name,
                        match i.component.version {
                            Some(v) => v,
                            None => { "None".to_string() }
                        },
                        i.vuln.id
                    );
                }
            }
            Err(err) => println!("[Error] {}", err),
        }
        let duration = start.elapsed();
        println!("Time elapsed in find_bug_bd_one_query() is: {:?}", duration);
    }

    #[tokio::test]
    async fn test_latex() {
        //let t = BD::default().await.expect("Error connect");
        let t = BD::new(&"postgresql://bdu:bdu@localhost:5438/bdu".to_string()).await.expect(
            "Error New"
        );
        match t.find(&"extra/cleaned_data.json".to_string(), true).await {
            Ok(bugs) => {
                match get_pdf(bugs, &"test".to_string()) {
                    Ok(_) => println!("Well done"),
                    Err(e) => println!("Well fuck: {}", e),
                };
            }
            Err(err) => println!("[Error] {}", err),
        }
    }

    #[tokio::test]
    async fn test_excel_file() {
        let t = BD::new(&"postgresql://bdu:bdu@localhost:5438/bdu".to_string()).await.expect(
            "Error New"
        );
        match t.find(&"extra/cleaned_data.json".to_string(), true).await {
            Ok(bugs) => {
                match get_excel(bugs, &"test_excel".to_string()) {
                    Ok(_) => println!("Excel report created: test_excel.xlsx"),
                    Err(e) => println!("Excel generation failed: {}", e),
                };
            }
            Err(err) => println!("[Error] {}", err),
        }
    }

    #[test]
    fn test_excel() {
        let file_name = "test_excel_report".to_string();
        let report_path = format!("{}.xlsx", file_name);

        let bug = Bugs {
            component: sbom5::Component {
                name: "openssl".to_string(),
                version: Some("1.1.1".to_string()),
                ..Default::default()
            },
            vuln: bdu::Component {
                id: "BDU:2024-0001".to_string(),
                name_vuln: Some("Тестовая уязвимость".to_string()),
                desc_vuln: Some("Описание тестовой уязвимости".to_string()),
                versions: vec![bdu::Version {
                    name: "openssl".to_string(),
                    from: Some("1.0.0".to_string()),
                    to: Some("1.1.1".to_string()),
                    inclusive: true,
                    only: None,
                }],
                date: Some("2024-01-01".to_string()),
                severity: Some("Высокий".to_string()),
                exploit: Some("Да".to_string()),
                fix: Some("Обновить пакет".to_string()),
                source_sites: Some(vec!["https://example.com/advisory".to_string()]),
                info: Some("Дополнительная информация".to_string()),
                ..Default::default()
            },
        };

        get_excel(vec![bug], &file_name).expect("failed to create xlsx report");

        let mut workbook: Xlsx<_> = open_workbook(&report_path).expect(
            "failed to open xlsx report"
        );
        let range = workbook.worksheet_range("Report").expect("failed to read report sheet");

        assert_eq!(range.get_value((0, 0)).expect("missing header").to_string(), "Компонент");
        assert_eq!(range.get_value((1, 0)).expect("missing component").to_string(), "openssl");
        assert_eq!(range.get_value((1, 1)).expect("missing version").to_string(), "1.1.1");
        assert_eq!(range.get_value((1, 2)).expect("missing vuln id").to_string(), "BDU:2024-0001");
        assert_eq!(
            range.get_value((1, 3)).expect("missing vuln name").to_string(),
            "Тестовая уязвимость"
        );
        assert_eq!(
            range.get_value((1, 4)).expect("missing vulnerable versions").to_string(),
            "Уязвима с версии 1.0.0 по версию 1.1.1 включительно"
        );

        fs::remove_file(report_path).expect("failed to delete xlsx report");
    }
    #[tokio::test]
    async fn test_typst() {}
}
