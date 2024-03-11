
use serde_derive::Deserialize;
use serde_derive::Serialize;

use std::path::Path;
use regex::Regex;

use calamine::{open_workbook, Reader, Xlsx};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    /// Идентификатор
    pub id: Option<String>,
    /// Наименование уязвимости         
    pub name_vuln: Option<String>,
    /// Описание уязвимости  
    pub desc_vuln: Option<String>,
    /// Вендор ПО
    pub vendor: Option<String>,
    /// Название ПО
    pub name: Option<String>,
    pub v_test: Option<Vec<String>>,
    /// Версия ПО
    pub versions: Option<Vec<Version>>,
    /// Тип ПО
    pub type_field: Option<String>,
    /// Наименование ОС и тип аппаратной платформы
    pub platforms: Option<Vec<String>>,
    /// Класс уязвимости
    pub class_vuln: Option<String>,
    /// Дата выявления
    pub date: Option<String>,
    /// CVSS 2.0
    pub cvss2: Option<String>,
    /// CVSS 3.0
    pub cvss3: Option<String>,
    /// Уровень опасности уязвимости
    pub severity: Option<String>,
    /// Возможные меры по устранению
    pub possible_fix: Option<String>,
    /// Статус уязвимости
    pub status_vuln: Option<String>,
    /// Наличие эксплойта
    pub exploit: Option<String>,
    /// Информация об устранении
    pub fix: Option<String>,
    /// Ссылки на источники
    pub source_sites: Option<Vec<String>>,
    /// Идентификаторы в других системах
    pub id_another_system: Option<Vec<String>>,
    /// Прочая информация
    pub info: Option<String>,
    /// Связь с инцидентами ИБ
    pub conn_is: Option<i64>,
    /// CWE
    pub cwe: Option<CWE>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub from: Option<String>,
    pub to: Option<String>,
    pub only: Option<String>,
    pub inclusive: bool,
    pub name: String
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CWE {
    /// Описание ошибки
    pub info: Option<Vec<String>>,
    /// Тип ошибки
    pub id: Option<Vec<String>>,
}

pub fn xlsx_parser(pt: &String, sheet_name: &String) -> Option<Vec<Component>> {
    let mut workbook: Xlsx<_> = open_workbook(Path::new(pt)).expect("Cannot open file");
    if let Ok(range) = workbook.worksheet_range(sheet_name) {
        let mut bdu_components: Vec<Component> = Vec::new();
        for hight in 3..range.get_size().0 {
            bdu_components.push(Component {
                id: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 0.try_into().unwrap()))
                        .expect("Not id")
                        .to_string(),
                ),
                name_vuln: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 1.try_into().unwrap()))
                        .expect("Not name_vuln")
                        .to_string(),
                ),
                desc_vuln: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 2.try_into().unwrap()))
                        .expect("desc_vuln")
                        .to_string(),
                ),
                vendor: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 3.try_into().unwrap()))
                        .expect("vendor")
                        .to_string(),
                ),
                name: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 4.try_into().unwrap()))
                        .expect("name")
                        .to_string(),
                ),
                v_test: Some(range
                    .get_value((hight.try_into().unwrap(), 5.try_into().unwrap()))
                    .expect("version")
                    .to_string()
                    .split(", ")
                    .map(&str::to_string)
                    .collect()
                ),
                versions: Some( 
                    {
                        let mut ret: Vec<Version> = Vec::new();
                        // TODO: добавить нормальные формы для всех полей
                        let re = Regex::new(r"^до (?<to_4>[а-яА-Яa-zA-Z0-9. \(\)-]+) включительно \((?<name_5>[[[:alnum:]][[:blank:]][а-яА-Я][[:punct:]]/–/-]+)\)$|(?<only>[[[:alnum:]][[:blank:]]\.\(\)]+) \((?<name_1>[[[:alnum:]][[:blank:]][а-яА-Я][[:punct:]]/–]+)\)$|^от (?<from_1>[а-яА-Яa-zA-Z0-9. \(\)]+) до (?<to_1>[а-яА-Яa-zA-Z0-9. \(\)]+) включительно \((?<name_2>[[[:alnum:]][[:blank:]][а-яА-Я][[:punct:]]/–]+)\)$|^от (?<from_2>[а-яА-Яa-zA-Z0-9. \(\)]+) до (?<to_2>[а-яА-Яa-zA-Z0-9. \(\)]+) \((?<name_3>[[[:alnum:]][[:blank:]][а-яА-Я][[:punct:]]/–]+)\)$|^до (?<to_3>[а-яА-Яa-zA-Z0-9. \(\)]+) \((?<name_4>[[[:alnum:]][[:blank:]][а-яА-Я][[:punct:]]/–]+)\)$").unwrap();
                        for version in range
                        .get_value((hight.try_into().unwrap(), 5.try_into().unwrap()))
                        .expect("version")
                        .to_string()
                        .split(", ")
                        .map(&str::to_string)
                        .into_iter() 
                        {
                            let Some(caps) = re.captures(&version) else {
                                continue;
                            };
                            ret.push(
                                Version {
                                    from: {
                                        let mut ret = "".to_string();
                                        let names = ["from_1", "from_2"];
                                        for name in names {
                                            let c = caps.name(name).map_or("", |m| m.as_str()).to_string();
                                            if c != "" {
                                                ret = c
                                            }
                                        } 
                                        Some(ret)
                                    },
                                    to: {
                                        let mut ret = "".to_string();
                                        let names = ["to_1", "to_2", "to_3", "to_4"];
                                        for name in names {
                                            let c = caps.name(name).map_or("", |m| m.as_str()).to_string();
                                            if c != "" {
                                                ret = c
                                            }
                                        } 
                                        Some(ret)
                                    },
                                    only: Some(caps.name("only").map_or("", |m| m.as_str()).to_string()),
                                    inclusive: {
                                        if caps.name("to_1").map_or("", |m| m.as_str()).to_string() != "" || caps.name("to_4").map_or("", |m| m.as_str()).to_string() != "" {
                                            true
                                        }else {
                                            false
                                        }
                                    },
                                    name: {
                                        let mut ret = "".to_string();
                                        let names = ["name_1", "name_2", "name_3", "name_4", "name_5"];
                                        for name in names {
                                            let c = caps.name(name).map_or("", |m| m.as_str()).to_string();
                                            if c != "" {
                                                ret = c
                                            }
                                        }
                                        ret
                                    },
                                }
                            )
                        }
                        ret
                    }
                ),
                type_field: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 6.try_into().unwrap()))
                        .expect("type_field")
                        .to_string(),
                ),
                platforms: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 7.try_into().unwrap()))
                        .expect("platform")
                        .to_string()
                        .split(", ")
                        .map(&str::to_string)
                        .collect(),
                ),
                class_vuln: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 8.try_into().unwrap()))
                        .expect("class_vuln")
                        .to_string(),
                ),
                date: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 9.try_into().unwrap()))
                        .expect("date")
                        .to_string(),
                ),
                cvss2: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 10.try_into().unwrap()))
                        .expect("cvss2")
                        .to_string(),
                ),
                cvss3: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 11.try_into().unwrap()))
                        .expect("cvss3")
                        .to_string(),
                ),
                severity: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 12.try_into().unwrap()))
                        .expect("severity")
                        .to_string(),
                ),
                possible_fix: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 13.try_into().unwrap()))
                        .expect("possible_fix")
                        .to_string(),
                ),
                status_vuln: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 14.try_into().unwrap()))
                        .expect("status_vuln")
                        .to_string(),
                ),
                exploit: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 15.try_into().unwrap()))
                        .expect("exploit")
                        .to_string(),
                ),
                fix: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 16.try_into().unwrap()))
                        .expect("fix")
                        .to_string(),
                ),
                source_sites: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 17.try_into().unwrap()))
                        .expect("source_sites")
                        .to_string()
                        .split("\n")
                        .map(str::to_string)
                        .collect(),
                ),
                id_another_system: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 18.try_into().unwrap()))
                        .expect("id_another_system")
                        .to_string()
                        .split(", ")
                        .map(str::to_string)
                        .collect(),
                ),
                info: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 19.try_into().unwrap()))
                        .expect("info")
                        .to_string(),
                ),
                conn_is: Some(
                    range
                        .get_value((hight.try_into().unwrap(), 20.try_into().unwrap()))
                        .expect("conn_is")
                        .to_string()
                        .parse()
                        .unwrap(),
                ),
                cwe: Some(CWE {
                    info: Some(
                        range
                            .get_value((hight.try_into().unwrap(), 21.try_into().unwrap()))
                            .expect("cwe info")
                            .to_string()
                            .split(", ")
                            .map(str::to_string)
                            .collect(),
                    ),
                    id: Some(
                        range
                            .get_value((hight.try_into().unwrap(), 22.try_into().unwrap()))
                            .expect("cwe id")
                            .to_string()
                            .split(", ")
                            .map(str::to_string)
                            .collect(),
                    ),
                }),
            })
        }
        Some(bdu_components)
    } else {
        None
    }
}
