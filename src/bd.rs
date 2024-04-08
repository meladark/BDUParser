use std::{ clone, default };

// extern crate postgres;
// use include_postgres_sql::{include_sql, impl_sql};
use crate::{ bdu::Component, sbom5 };
use postgres::{ Client, NoTls };
use regex::Regex;

pub struct BD {
    client: String,
}

impl BD {
    pub fn new(postgres_url: &String) -> Self {
        Self {
            client: postgres_url.to_string(),
        }
    }
    pub fn update(&self, components: &Vec<Component>) -> Result<(), String> {
        return connect(&self.client, components);
    }
    pub fn find(&self, sbom: &sbom5::Root) {
        find_bug_bd_one_query(&self.client, sbom);
    }
}

impl Default for BD {
    fn default() -> Self {
        Self {
            client: "postgresql://bdu:bdu@localhost:5433/bdu".to_string(),
        }
    }
}

#[allow(dead_code)]
/// Пример ``
fn connect(host: &String, components: &Vec<Component>) -> Result<(), String> {
    let mut client = Client::connect(host, NoTls).expect("Error connect");
    client
        .batch_execute(
            "
        BEGIN;
        CREATE TABLE IF NOT EXISTS public.\"BDU_platform\"
        (
            id serial,
            bdu_id text,
            platform integer,
            PRIMARY KEY (id)
        );

        CREATE TABLE IF NOT EXISTS public.platform
        (
            name text COLLATE pg_catalog.\"default\",
            version text COLLATE pg_catalog.\"default\",
            pkey serial,
            CONSTRAINT platform_pkey PRIMARY KEY (pkey)
        );

        CREATE TABLE IF NOT EXISTS public.\"BDU\"
        (
            id text COLLATE pg_catalog.\"default\" NOT NULL,
            name text COLLATE pg_catalog.\"default\",
            \"desc\" text COLLATE pg_catalog.\"default\",
            vendors text[] COLLATE pg_catalog.\"default\",
            software_types text[] COLLATE pg_catalog.\"default\",
            class text COLLATE pg_catalog.\"default\",
            date text COLLATE pg_catalog.\"default\",
            cvss2 text COLLATE pg_catalog.\"default\",
            cvss3 text COLLATE pg_catalog.\"default\",
            severity text COLLATE pg_catalog.\"default\",
            possible_fix text COLLATE pg_catalog.\"default\",
            status text COLLATE pg_catalog.\"default\",
            exploit text COLLATE pg_catalog.\"default\",
            fix text COLLATE pg_catalog.\"default\",
            source_sites text[] COLLATE pg_catalog.\"default\",
            id_another_system text[] COLLATE pg_catalog.\"default\",
            info text COLLATE pg_catalog.\"default\",
            conn_is integer,
            \"CWE_info\" text[] COLLATE pg_catalog.\"default\",
            \"CWE_id\" text[] COLLATE pg_catalog.\"default\",
            CONSTRAINT \"BDU_pkey\" PRIMARY KEY (id)
        );

        COMMENT ON TABLE public.\"BDU\"
            IS 'Уязвимости спаршенные с бду. ';

        CREATE TABLE IF NOT EXISTS public.components
        (
            id serial,
            name text COLLATE pg_catalog.\"default\",
            \"from\" text COLLATE pg_catalog.\"default\",
            \"to\" text COLLATE pg_catalog.\"default\",
            \"only\" text COLLATE pg_catalog.\"default\",
            inclusive boolean,
            from_major integer,
            from_minor integer,
            from_patch integer,
            to_major integer,
            to_minor integer,
            to_patch integer,
            id_bdu text COLLATE pg_catalog.\"default\",
            CONSTRAINT components_pkey PRIMARY KEY (id)
        );

        ALTER TABLE IF EXISTS public.\"BDU_platform\"
            ADD FOREIGN KEY (platform)
            REFERENCES public.platform (pkey) MATCH SIMPLE
            ON UPDATE NO ACTION
            ON DELETE NO ACTION
            NOT VALID;


        ALTER TABLE IF EXISTS public.\"BDU_platform\"
            ADD FOREIGN KEY (bdu_id)
            REFERENCES public.\"BDU\" (id) MATCH SIMPLE
            ON UPDATE NO ACTION
            ON DELETE NO ACTION
            NOT VALID;


        ALTER TABLE IF EXISTS public.components
            ADD FOREIGN KEY (id_bdu)
            REFERENCES public.\"BDU\" (id) MATCH SIMPLE
            ON UPDATE NO ACTION
            ON DELETE NO ACTION
            NOT VALID;

        END;"
        )
        .expect("Error batch_execute");

    // let name = "Ferris";
    // let data = None::<&[u8]>;
    // client.execute(
    //     "INSERT INTO person (name, data) VALUES ($1, $2)",
    //     &[&name, &data],
    // ).expect("Error execute");
    // let component = Component {
    //     id: "BDU:2023-03670".to_string(),
    //     name_vuln: Some(
    //         "Уязвимость реализации протокола Bluetooth Classic спецификации Bluetooth Core Specification, позволяющая нарушителю раскрыть защищаемую информацию".to_string()
    //     ),
    //     desc_vuln: Some(
    //         "Уязвимость функции mctp_unregister() ядра операционных систем Linux связана с использованием памяти после ее освобождения при обработке объекта mdev->addrs. Эксплуатация уязвимости может позволить нарушителю вызвать отказ в обслуживании".to_string()
    //     ),
    //     vendors: Some(
    //         [
    //             "ООО «РусБИТех-Астра»".to_string(),
    //             "ООО «Ред Софт»".to_string(),
    //             "Сообщество свободного программного обеспечения".to_string(),
    //         ].to_vec()
    //     ),
    //     name: Some(
    //         [
    //             "Astra Linux Special Edition (запись в едином реестре российских программ №369)".to_string(),
    //             "РЕД ОС (запись в едином реестре российских программ №3751)".to_string(),
    //             "Linux".to_string(),
    //         ].to_vec()
    //     ),
    //     v_test: Some([].to_vec()),
    //     versions: Some(
    //         [
    //             Version {
    //                 from: Some("".to_string()),
    //                 to: Some("".to_string()),
    //                 only: Some("7.3".to_string()),
    //                 inclusive: false,
    //                 name: "РЕД ОС".to_string(),
    //             },
    //             Version {
    //                 from: Some("".to_string()),
    //                 to: Some("".to_string()),
    //                 only: Some("1.7".to_string()),
    //                 inclusive: false,
    //                 name: "Astra Linux Special Edition".to_string(),
    //             },
    //             Version {
    //                 from: Some("5.15".to_string()),
    //                 to: Some("5.17.5".to_string()),
    //                 only: Some("".to_string()),
    //                 inclusive: true,
    //                 name: "Linux".to_string(),
    //             },
    //         ].to_vec()
    //     ),
    //     software_types: Some(["Операционная система".to_string()].to_vec()),
    //     v_platforms: Some([].to_vec()),
    //     platforms: Some(
    //         [
    //             Platform {
    //                 name: Some("Astra Linux Special Edition".to_string()),
    //                 version: Some(
    //                     "1.6 «Смоленск»; запись в едином реестре российских программ №369".to_string()
    //                 ),
    //             },
    //             Platform {
    //                 name: Some("РЕД ОС".to_string()),
    //                 version: Some(
    //                     "7.3; запись в едином реестре российских программ №3751".to_string()
    //                 ),
    //             },
    //             Platform {
    //                 name: Some("Astra Linux Special Edition".to_string()),
    //                 version: Some(
    //                     "1.7; запись в едином реестре российских программ №369".to_string()
    //                 ),
    //             },
    //             Platform {
    //                 name: Some("Linux".to_string()),
    //                 version: Some("от 5.15 до 5.17.5 включительно".to_string()),
    //             },
    //         ].to_vec()
    //     ),
    //     class_vuln: Some("Уязвимость кода".to_string()),
    //     date: Some("22.04.2022".to_string()),
    //     cvss2: Some("AV:L/AC:L/Au:S/C:N/I:N/A:C".to_string()),
    //     cvss3: Some("AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H".to_string()),
    //     severity: Some(
    //         "Средний уровень опасности (базовая оценка CVSS 2.0 составляет 4,6)\nСредний уровень опасности (базовая оценка CVSS 3.0 составляет 5,5)".to_string()
    //     ),
    //     possible_fix: Some(
    //         "Использование рекомендаций:\nhttps://kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.17.6\n\nДля РедОС: http://repo.red-soft.ru/redos/7.3c/x86_64/updates/\n\nДля ОС Astra Linux Special Edition 1.7:\nобновить пакет linux-5.15 до 5.15.0-83.astra1+ci14 или более высокой версии, используя рекомендации производителя: https://wiki.astralinux.ru/astra-linux-se17-bulletin-2023-1023SE17\n\nДля Astra Linux 1.6 «Смоленск»:\nобновить пакет linux-5.15 до 5.15.0-83.astra1+ci36 или более высокой версии, используя рекомендации производителя: https://wiki.astralinux.ru/astra-linux-se16-bulletin-20231214SE16".to_string()
    //     ),
    //     status_vuln: Some("Подтверждена производителем".to_string()),
    //     exploit: Some("Существует в открытом доступе".to_string()),
    //     fix: Some("Уязвимость устранена".to_string()),
    //     source_sites: Some(
    //         [
    //             "https://www.linuxkernelcves.com/cves/CVE-2023-3439".to_string(),
    //             "https://access.redhat.com/security/cve/CVE-2023-3439".to_string(),
    //             "https://kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.17.6".to_string(),
    //             "http://www.openwall.com/lists/oss-security/2023/07/02/1 ".to_string(),
    //             "https://bugzilla.redhat.com/show_bug.cgi?id=2217915".to_string(),
    //             "http://repo.red-soft.ru/redos/7.3c/x86_64/updates/".to_string(),
    //             "https://wiki.astralinux.ru/astra-linux-se17-bulletin-2023-1023SE17".to_string(),
    //             "https://wiki.astralinux.ru/astra-linux-se16-bulletin-20231214SE16".to_string(),
    //         ].to_vec()
    //     ),
    //     id_another_system: Some(["CVE-2023-3439".to_string()].to_vec()),
    //     info: Some("".to_string()),
    //     conn_is: Some(0),
    //     cwe: CWE {
    //         info: Some(
    //             [
    //                 "Одновременное выполнение с использованием общего ресурса с неправильной синхронизацией («Ситуация гонки»)".to_string(),
    //                 "Использование после освобождения".to_string(),
    //             ].to_vec()
    //         ),
    //         id: Some(["CWE-362".to_string(), "CWE-416".to_string()].to_vec()),
    //     },
    // };
    let re = Regex::new(
        r"^(?<major_full>[[:digit:]]+)\.(?<minor_full>[[:digit:]]+)\.(?<patch_full>[[:digit:]]+)|^(?<major_sep>[[:digit:]]+)\.(?<minor_sep>[[:digit:]]+)|^(?<major_only>[[:digit:]]+)"
    ).unwrap();
    for component in components {
        let _k = client
            .query(
                "SELECT public.\"BDU\".id FROM public.\"BDU\" WHERE public.\"BDU\".id = $1 LIMIT 1",
                &[&component.id]
            )
            .expect("pizdec query");
        if _k.len() > 0 {
            //print!("Exist!")
        } else {
            //print!("Not Exist!");
            // TODO: Настроить правильные поля, к примеру время как время
            let _ = client
                .execute(
                    "INSERT INTO public.\"BDU\" (
                id, 
                name, 
                \"desc\", 
                vendors, 
                software_types, 
                class, 
                date, 
                cvss2, 
                cvss3, 
                severity, 
                possible_fix, 
                status, 
                exploit, 
                fix, 
                source_sites, 
                id_another_system, 
                info, 
                conn_is, 
                \"CWE_info\", 
                \"CWE_id\") 
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)",
                    &[
                        &component.id,
                        &component.name_vuln,
                        &component.desc_vuln,
                        &component.vendors,
                        &component.software_types,
                        &component.class_vuln,
                        &component.date,
                        &component.cvss2,
                        &component.cvss3,
                        &component.severity,
                        &component.possible_fix,
                        &component.status_vuln,
                        &component.exploit,
                        &component.fix,
                        &component.source_sites,
                        &component.id_another_system,
                        &component.info,
                        &component.conn_is,
                        &component.cwe.info,
                        &component.cwe.id,
                    ]
                )
                .expect("pizdec");
            if let Some(versions) = &component.versions {
                if versions.len() > 0 {
                    for version in versions {
                        let _ = client
                            .execute(
                                "INSERT INTO public.components (
                                        name, 
                                        \"from\", 
                                        \"to\", 
                                        \"only\", 
                                        inclusive, 
                                        from_major, 
                                        from_minor, 
                                        from_patch, 
                                        to_major, 
                                        to_minor, 
                                        to_patch, 
                                        id_bdu
                                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                                &[
                                    &Some(&version.name),
                                    &Some(&version.from),
                                    &Some(&version.to),
                                    &Some(&version.only),
                                    &Some(&version.inclusive),
                                    {
                                        let mut ret = 0_i32;
                                        if let Some(from) = &version.from {
                                            let names = ["major_full", "major_sep", "major_only"];
                                            if let Some(caps) = re.captures(&from) {
                                                for name in names {
                                                    if let Some(c) = caps.name(name) {
                                                        let nop = c.as_str().parse::<i32>();
                                                        if !nop.is_err() {
                                                            ret = nop.unwrap();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        &Some(ret)
                                    },
                                    {
                                        let mut ret = 0_i32;
                                        if let Some(from) = &version.from {
                                            let names = ["minor_full", "minor_sep"];
                                            if let Some(caps) = re.captures(&from) {
                                                for name in names {
                                                    if let Some(c) = caps.name(name) {
                                                        let nop = c.as_str().parse::<i32>();
                                                        if !nop.is_err() {
                                                            ret = nop.unwrap();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        &Some(ret)
                                    },
                                    {
                                        let mut ret = 0_i32;
                                        if let Some(from) = &version.from {
                                            let names = ["patch_full"];
                                            if let Some(caps) = re.captures(&from) {
                                                for name in names {
                                                    if let Some(c) = caps.name(name) {
                                                        let nop = c.as_str().parse::<i32>();
                                                        if !nop.is_err() {
                                                            ret = nop.unwrap();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        &Some(ret)
                                    },
                                    {
                                        let mut ret = 0_i32;
                                        if let Some(to) = &version.to {
                                            let names = ["major_full", "major_sep", "major_only"];
                                            if let Some(caps) = re.captures(&to) {
                                                for name in names {
                                                    if let Some(c) = caps.name(name) {
                                                        let nop = c.as_str().parse::<i32>();
                                                        if !nop.is_err() {
                                                            ret = nop.unwrap();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        &Some(ret)
                                    },
                                    {
                                        let mut ret = 0_i32;
                                        if let Some(to) = &version.to {
                                            let names = ["minor_full", "minor_sep"];
                                            if let Some(caps) = re.captures(&to) {
                                                for name in names {
                                                    if let Some(c) = caps.name(name) {
                                                        let nop = c.as_str().parse::<i32>();
                                                        if !nop.is_err() {
                                                            ret = nop.unwrap();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        &Some(ret)
                                    },
                                    {
                                        let mut ret = 0_i32;
                                        if let Some(to) = &version.to {
                                            let names = ["patch_full"];
                                            if let Some(caps) = re.captures(&to) {
                                                for name in names {
                                                    if let Some(c) = caps.name(name) {
                                                        let nop = c.as_str().parse::<i32>();
                                                        if !nop.is_err() {
                                                            ret = nop.unwrap();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        &Some(ret)
                                    },
                                    &component.id,
                                ]
                            )
                            .expect("pizdec");
                    }
                } else {
                    if let Some(names) = &component.name {
                        for name in names {
                            let _ = client
                                .execute(
                                    "INSERT INTO public.components (
                                    name, 
                                    \"from\", 
                                    \"to\", 
                                    \"only\", 
                                    inclusive, 
                                    from_major, 
                                    from_minor, 
                                    from_patch, 
                                    to_major, 
                                    to_minor, 
                                    to_patch, 
                                    id_bdu
                                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                                    &[
                                        &name,
                                        &"".to_string(),
                                        &"".to_string(),
                                        &"".to_string(),
                                        &false,
                                        &0_i32,
                                        &0_i32,
                                        &0_i32,
                                        &0_i32,
                                        &0_i32,
                                        &0_i32,
                                        &component.id,
                                    ]
                                )
                                .expect("pizdec");
                        }
                    }
                }
            } else {
                print!("No version {}", &component.id);
            }
            if let Some(platforms) = &component.platforms {
                for platform in platforms {
                    let pl = client
                        .query(
                            "SELECT public.platform.pkey FROM public.platform WHERE ((name = $1) AND (version = $2)) LIMIT 1",
                            &[&platform.name, &platform.version]
                        )
                        .expect("pizdec");
                    if pl.len() > 0 {
                        for r in pl {
                            // TODO: по сути оно не нужно, так как не может быть иначе
                            let _id: i32 = r.get(0);
                            let _ = client
                                .execute(
                                    "INSERT INTO public.\"BDU_platform\" (
                                        \"bdu_id\", 
                                        platform
                                    ) VALUES ($1, $2)",
                                    &[&component.id, &_id]
                                )
                                .expect("pizdec");
                        }
                        continue;
                    }
                    let pl = client
                        .query(
                            "INSERT INTO public.platform (name, version) VALUES ($1, $2) returning pkey",
                            &[&platform.name, &platform.version]
                        )
                        .expect("pizdec platform");
                    for r in pl {
                        // TODO: по сути оно не нужно, так как не может быть иначе
                        let _id: i32 = r.get(0);
                        let _ = client
                            .execute(
                                "INSERT INTO public.\"BDU_platform\" (\"bdu_id\", platform) VALUES ($1, $2)",
                                &[&component.id, &_id]
                            )
                            .expect("pizdec");
                    }
                }
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn find_bug_bd_one_query(host: &String, sbom: &sbom5::Root) {
    let mut client = Client::connect(host, NoTls).expect("Error connect");
    let mut query = String::from(
        "SELECT public.\"BDU\".id, public.\"BDU\".name, public.components.name FROM public.\"BDU\" INNER JOIN public.components ON public.\"BDU\".id = components.\"id_bdu\" WHERE"
    );

    if let Some(sbom_components) = &sbom.components {
        if sbom_components.len() > 0 {
            let mut or = "";
            for component in sbom_components {
                query.push_str(&format!(" {} public.components.name = '{}'", or, component.name));
                or = "OR"; // =) Debil'
            }
            query.push_str(";");
            for row in client.query(&query, &[]).expect("pizdec") {
                let id: &str = row.get(0);
                let name: &str = row.get(1);
                let name_: &str = row.get(2);
                println!("Name: {} BDU id: {}, BDU name: {}", name_, id, name);
            }
        }
    }
}
