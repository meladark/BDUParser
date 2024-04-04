use calamine::{ open_workbook, Reader, Xlsx };
use serde::{ Deserialize, Serialize };
use serde_json::{ Result, Value };
use std::{ fs, path::Path };

mod bdu;
mod sbom4;
mod sbom5;
mod bd;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct Bom {
    //Deprecated
    bomFormat: String,
    specVersion: String,
    serialNumber: String,
    version: u8,
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub fn read_bdu(pt: String, sheet_name: String) {
    let mut workbook: Xlsx<_> = open_workbook(Path::new(&pt)).expect("Cannot open file");
    // if let Ok(range) = workbook.worksheet_range(&sheet_name) {
    //     let total_cells = range.get_size().0 * range.get_size().1;
    //     let non_empty_cells: usize = range.used_cells().count();
    //     println!("Found {} cells in 'Sheet', including {} non empty cells",
    //              total_cells, non_empty_cells);
    //     // alternatively, we can manually filter rows
    //     assert_eq!(non_empty_cells, range.rows()
    //         .flat_map(|r| r.iter().filter(|&c| c != &Data::Empty)).count());
    // }
    if let Ok(range) = workbook.worksheet_range(&sheet_name) {
        for h in 3..5 {
            for w in 0..range.get_size().1 {
                let total_cells = range
                    .get_value((h.try_into().unwrap(), w.try_into().unwrap()))
                    .expect("Not position");
                print!("{} ", total_cells);
            }
            println!("\n----------");
        }
    }
}

#[allow(dead_code)]
fn sbom_read(pt: String) -> Result<()> {
    let foo = fs::read_to_string(Path::new(&pt)).expect("Bad File");
    println!("File {}", pt);
    let t: Value = serde_json::from_str(&foo)?;
    if let Some(field) = t.get("specVersion") {
        if field == "1.4" {
            println!("Run parse 1.4");
            let sbom = serde_json::from_str::<sbom4::Root>(&foo).expect("Bad json");
            if let Some(components) = sbom.components {
                for component in components {
                    print!("{}|", component.name);
                }
            }
            println!("Parse Done");
        } else if field == "1.5" {
            println!("Run parse 1.5");
            let _ = serde_json::from_str::<sbom5::Root>(&foo)?;
            println!("Parse Done");
        }
    }
    // println!("{:?}", t);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{ fs::File, io::{ BufWriter, Write }, time::Instant };

    use crate::bd::find_bug_bd_one_query;

    use self::{ bd::{ connect_create, find_bug_bd }, bdu::{ find_bugs, xlsx_parser } };

    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
    #[test]
    fn test_read_bdu() {
        read_bdu(String::from("/home/mike/EXTERNAL/bdu/vullist.xlsx"), String::from("Sheet"));
    }
    #[test]
    fn test_read_json() {
        let _ = sbom_read(String::from("/home/mike/EXTERNAL/bdu/bom.json"));
        let _ = sbom_read(String::from("/home/mike/EXTERNAL/bdu/bom.1.4.json"));
        let _ = sbom_read(String::from("/home/mike/EXTERNAL/bdu/bom (1).json"));
    }
    #[test]
    fn test_bdu_parser() {
        let bdu_components = xlsx_parser(
            &String::from("/home/mike/EXTERNAL/bdu/vullist.xlsx"),
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
    fn test_find_bugs() {
        let bdu_components = xlsx_parser(
            &String::from("/home/mike/EXTERNAL/bdu/vullist.xlsx"),
            &String::from("Sheet")
        );
        let sbom = sbom4::read_sbom(String::from("/home/mike/EXTERNAL/bdu/bom.1.4.json"));
        if let Some(bdu4ka) = bdu_components {
            let start = Instant::now();
            find_bugs(&bdu4ka, &sbom);
            let duration = start.elapsed();
            println!("Time elapsed in find_bugs() is: {:?}", duration);
        }
    }
    #[test]
    fn test_postgres() {
        let bdu_components = xlsx_parser(
            &String::from("/home/mike/EXTERNAL/bdu/vullist.xlsx"),
            &String::from("Sheet")
        );
        if let Some(ebu4ka) = bdu_components {
            connect_create(&ebu4ka);
        }
        //connect_create();
    }
    #[test]
    fn test_find_bug_bd() {
        let sbom = sbom4::read_sbom(String::from("/home/mike/EXTERNAL/bdu/bom.1.4.json"));
        let start = Instant::now();
        find_bug_bd(&sbom);
        let duration = start.elapsed();
        println!("Time elapsed in find_bug_bd() is: {:?}", duration);
    }
    #[test]
    fn test_find_bug_bd_one_query() {
        let sbom = sbom4::read_sbom(String::from("/home/mike/EXTERNAL/bdu/bom.1.4.json"));
        let start = Instant::now();
        find_bug_bd_one_query(&sbom);
        let duration = start.elapsed();
        println!("Time elapsed in find_bug_bd_one_query() is: {:?}", duration);
    }
}
