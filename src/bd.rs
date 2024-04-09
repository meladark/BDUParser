use std::{ fs, process::Command };

// #![crate_name = "doc"]
use crate::{ bdu::{ self, xlsx_parser, Component }, sbom5 };
use postgres::{ types::Json, Client, NoTls };
use regex::Regex;
use serde_json::json;

pub struct Bugs {
    pub component: sbom5::Component,
    pub vuln: bdu::Component,
}

pub struct BD {
    ///
    client: String,
}

impl BD {
    #[allow(dead_code)]
    /// Создание нового подключения.
    /// Подключение происходит при каждом вызове методов.
    /// Тут лишь сохраняются параметры.
    ///
    /// # Arguments
    ///
    /// * `postgres_url` - Параметры подключения к Постгрес.
    ///
    /// # Example
    ///
    /// Пример для урла - *postgresql://bdu:bdu@localhost:5433/bdu*
    pub fn new(postgres_url: &String) -> Self {
        Self {
            client: postgres_url.to_string(),
        }
    }
    #[allow(dead_code)]
    pub fn update(&self) -> Result<(), String> {
        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", "Windows doesn`t support yet"])
                .output()
                .expect("failed to execute process");
            return Err("Windows platform doesn`t support yet".to_string());
        } else {
            Command::new("wget")
                .arg("--no-check-certificate")
                .arg("https://bdu.fstec.ru/files/documents/vullist.xlsx")
                .arg("-O")
                .arg("vull.xlsx")
                .output()
                .expect("failed to execute process")
        };
        if output.status.success() {
            let bdu_components = xlsx_parser(&String::from("vull.xlsx"), &String::from("Sheet"));
            fs::remove_file("vull.xlsx").expect("Error delete vull.xlsx");
            if let Some(components) = bdu_components {
                return connect(&self.client, &components);
            } else {
                return Err("Faild to parse xlsx BDU".to_string());
            }
        } else {
            return Err(
                format!(
                    "Get BDU database error: Message: {} Status: {}",
                    String::from_utf8(output.stdout).expect("pizdec conver"),
                    output.status
                )
            );
        }
    }
    #[allow(dead_code)]
    pub fn find(&self, foo: &String) -> Result<Vec<Bugs>, String> {
        let sbom = serde_json::from_str::<sbom5::Root>(foo).expect("Bad json");
        let mut client = Client::connect(&self.client, NoTls).expect("Error connect");
        let ans = client
            .query(
                "
            INSERT INTO public.\"SBOM_raw\" (sbom) VALUES ($1) RETURNING id;
            ",
                &[&json!(&foo)]
            )
            .expect("Error insert");
        let mut _id = ans[0].get::<_, i32>(0);
        let mut count = 0;
        if let Some(sbom_component) = &sbom.components {
            let re = Regex::new(r"(?<major>\d+).(?<minor>\d+).(?<patch>\d+)").expect("Error regex");
            for component in sbom_component {
                let row = client.execute(
                    "INSERT INTO public.sbom_components (name, version, major, minor, patch, \"SBOM_raw\", \"raw\") VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    &[
                        &component.name,
                        &Some(&component.version),
                        {
                            let mut ret = 0_i32;
                            if let Some(ver) = &component.version {
                                if let Some(caps) = re.captures(&ver) {
                                    if let Some(c) = caps.name("major") {
                                        let nop = c.as_str().parse::<i32>();
                                        if !nop.is_err() {
                                            ret = nop.unwrap();
                                        }
                                    }
                                }
                            }
                            &Some(ret)
                        },
                        {
                            let mut ret = 0_i32;
                            if let Some(ver) = &component.version {
                                if let Some(caps) = re.captures(&ver) {
                                    if let Some(c) = caps.name("minor") {
                                        let nop = c.as_str().parse::<i32>();
                                        if !nop.is_err() {
                                            ret = nop.unwrap();
                                        }
                                    }
                                }
                            }
                            &Some(ret)
                        },
                        {
                            let mut ret = 0_i32;
                            if let Some(ver) = &component.version {
                                if let Some(caps) = re.captures(&ver) {
                                    if let Some(c) = caps.name("patch") {
                                        let nop = c.as_str().parse::<i32>();
                                        if !nop.is_err() {
                                            ret = nop.unwrap();
                                        }
                                    }
                                }
                            }
                            &Some(ret)
                        },
                        &_id,
                        &json!(&component),
                    ]
                );
                match row {
                    Ok(_) => {
                        count += 1;
                    }
                    Err(err) => println!("[Error] Error add sbom component to postgres: {}", err),
                }
            }
            println!("[Info] Add {}/{} sbom components.", count, sbom_component.len());
        } else {
            return Err("No one sbom components".to_string());
        }
        find_bug_bd_one_query(&self.client, _id)
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
            \"raw\" json,
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
    client
        .batch_execute(
            "
            BEGIN;
            CREATE TABLE IF NOT EXISTS public.\"SBOM_raw\"
            (
                id serial,
                sbom json,
                PRIMARY KEY (id)
            );
            
            CREATE TABLE IF NOT EXISTS public.sbom_components
            (
                id serial,
                name text,
                version text,
                major integer,
                minor integer,
                patch integer,
                \"SBOM_raw\" integer,
                \"raw\" json,
                PRIMARY KEY (id)
            );
            
            ALTER TABLE IF EXISTS public.sbom_components
                ADD FOREIGN KEY (\"SBOM_raw\")
                REFERENCES public.\"SBOM_raw\" (id) MATCH SIMPLE
                ON UPDATE NO ACTION
                ON DELETE NO ACTION
                NOT VALID;
            
            END;"
        )
        .expect("Error create components database");
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
                \"CWE_id\",
                \"raw\") 
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)",
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
                        &json!(component),
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
fn find_bug_bd_one_query(host: &String, id: i32) -> Result<Vec<Bugs>, String> {
    let mut client = Client::connect(host, NoTls).expect("Error connect");
    let row = client.query(
        "SELECT public.sbom_components.\"raw\", public.\"BDU\".\"raw\"
	FROM public.sbom_components 
	INNER JOIN public.components 
	ON public.sbom_components.name = public.components.name INNER JOIN public.\"BDU\" ON public.components.id_bdu = public.\"BDU\".id
	WHERE public.sbom_components.\"SBOM_raw\" = $1;",
        &[&id]
    );
    let mut bugs = Vec::<Bugs>::new();
    match row {
        Ok(row) =>
            for r in row {
                bugs.push(Bugs {
                    component: r.get::<_, Json<sbom5::Component>>(0).0,
                    vuln: r.get::<_, Json<bdu::Component>>(1).0,
                });
            }
        Err(err) => print!("{}", err),
    }
    Ok(bugs)
}
