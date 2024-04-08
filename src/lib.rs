use std::process::Command;

use serde::{ Deserialize, Serialize };
use serde_json::Value;

mod bd;
mod bdu;
mod sbom4;
mod sbom5;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct Bom {
    //Deprecated
    bomFormat: String,
    specVersion: String,
    serialNumber: String,
    version: u8,
}

#[allow(dead_code)]
/// Чтение [Sbom](https://github.com/CycloneDX) как строку и возвращает готовую структуру, либо ошибку.
fn sbom_read(foo: String) -> Result<sbom5::Root, String> {
    let t: Value = serde_json::from_str(&foo).expect("Parsing json");
    if let Some(field) = t.get("specVersion") {
        if field == "1.5" {
            let sbom = serde_json::from_str::<sbom5::Root>(&foo).expect("Bad json");
            Ok(sbom)
        } else {
            Err(format!("Bad specVersion file. Must be 1.5 at least: {}", field))
        }
    } else {
        Err("No specVersion in file".to_string())
    }
}
/// Загрузить [Sbom](https://github.com/CycloneDX)
pub fn set_sbom(pt: &String) -> Result<sbom5::Root, String> {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "Windows doesn`t support yet"])
            .output()
            .expect("failed to execute process");
        return Err("Windows platform doesn`t support yet".to_string());
    } else {
        Command::new("./cyclonedx-linux-x64")
            .arg("convert")
            .args(["--input-file", pt, "--output-format", "json", "--output-version", "v1_5"])
            .output()
            .expect("failed to execute process")
    };
    if output.status.success() {
        return sbom_read(String::from_utf8(output.stdout).expect("pizdec conver"));
    } else {
        return Err(
            format!(
                "Convert Error: Message: {} Status: {}",
                String::from_utf8(output.stdout).expect("pizdec conver"),
                output.status
            )
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{ fs::{ self, File }, io::{ BufWriter, Write }, path::Path, time::Instant };

    use crate::bd::BD;

    use self::bdu::xlsx_parser;

    use super::*;

    #[test]
    fn test_read_json() {
        let all_files = [
            "extra/bom.json",
            "extra/bom.1.4.json",
            "extra/bom (1).json",
            "extra/bom.1.5.json",
            "extra/badfile",
            "extra/vullist.xlsx",
        ];
        for file in all_files {
            println!("File {}", &file);
            match set_sbom(&file.to_string()) {
                Ok(_) => println!("Parse Done"),
                Err(err) => println!("{}", err),
            };
        }
    }
    #[test]
    fn test_bdu_parser() {
        let bdu_components = xlsx_parser(
            &String::from("extra/vullist.xlsx"),
            &String::from("Sheet")
        );
        if let Some(components) = bdu_components {
            let file = File::create("bdu.json").expect("File bad");
            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, &components[47000..48000]).expect("Kall");
            writer.flush().expect("Pizdec");
        } else {
            println!("Обосрался")
        }
    }
    #[test]
    fn test_postgres() {
        let bdu_components = xlsx_parser(
            &String::from("extra/vullist.xlsx"),
            &String::from("Sheet")
        );
        if let Some(ebu4ka) = bdu_components {
            let _ = BD::default().update(&ebu4ka);
        }
        //connect_create();
    }
    #[test]
    fn test_find_bug_bd_one_query() {
        let sbom = sbom_read(
            String::from(fs::read_to_string(Path::new("extra/bom.1.5.json")).expect("Bad File"))
        );
        let start = Instant::now();
        match sbom {
            Ok(sbom) => BD::default().find(&sbom),
            Err(err) => println!("Error: {}", err),
        }
        let duration = start.elapsed();
        println!("Time elapsed in find_bug_bd_one_query() is: {:?}", duration);
    }
}
