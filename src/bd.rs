use std::{ fs, process::Command };

// #![crate_name = "doc"]
use crate::{ bdu::{ self, xlsx_parser, Component }, sbom5 };
use postgres::types::Json;
use regex::Regex;
use serde_json::json;
use log::{ debug, error, info, trace };
use tokio_postgres::NoTls;
use tempdir::TempDir;

#[derive(Debug)]
pub struct Bugs {
    pub component: sbom5::Component,
    pub vuln: bdu::Component,
}

pub struct BD {
    ///
    client: tokio_postgres::Client,
}

impl BD {
    #[allow(dead_code)]
    /// Создание нового подключения.
    ///
    /// # Arguments
    ///
    /// * `postgres_url` - Параметры подключения к Постгрес.
    ///
    /// # Example
    ///
    /// Пример для урла - *postgresql://bdu:bdu@localhost:5433/bdu*
    pub async fn new(postgres_url: &String) -> Result<Self, String> {
        info!("Start new connection on {}", postgres_url);
        match tokio_postgres::connect(&postgres_url, NoTls).await {
            Ok((_client, _connection)) => {
                tokio::spawn(async move {
                    if let Err(e) = _connection.await {
                        error!("Connection async move error: {}", e);
                    }
                });
                Ok(Self {
                    client: _client,
                })
            }
            Err(err) => {
                error!("Error connect: {}", err);
                Err(format!("Error connect: {}", err))
            }
        }
    }
    /// Создание нового default подключения.
    /// Стандартное подключение - *postgresql://bdu:bdu@localhost:5433/bdu*
    pub async fn default() -> Result<Self, String> {
        info!("Start default connection");
        match
            tokio_postgres::connect(
                &"postgresql://bdu:bdu@localhost:5433/bdu".to_string(),
                NoTls
            ).await
        {
            Ok((_client, _connection)) => {
                tokio::spawn(async move {
                    if let Err(e) = _connection.await {
                        error!("Connection error: {}", e);
                    }
                });
                Ok(Self {
                    client: _client,
                })
            }
            Err(err) => {
                error!("Error connect: {}", err);
                Err(format!("Error connect: {}", err))
            }
        }
    }

    async fn find_bug_bd_one_query(&self, id: i32, full: bool) -> Result<Vec<Bugs>, String> {
        info!("Start findings bugs!");
        let query;
        if full {
            query =
                "SELECT public.sbom_components.\"raw\", public.\"BDU\".\"raw\"
            FROM public.sbom_components 
            INNER JOIN public.components 
            ON public.sbom_components.name = public.components.name INNER JOIN public.\"BDU\" ON public.components.id_bdu = public.\"BDU\".id
            WHERE public.sbom_components.\"SBOM_raw\" = $1 ORDER BY public.sbom_components.name ASC, public.sbom_components.version ASC;";
        } else {
            query =
                "SELECT
                --public.sbom_components.\"version\",
                --public.components.only,
                --sbom_components.major,
                --public.sbom_components.minor,
                --public.sbom_components.patch,
                --public.components.inclusive,
                --public.components.from_major,
                --public.components.from_minor,
                --public.components.from_patch,
                --public.components.to_major,
                --public.components.to_minor,
                --public.components.to_patch,
                public.sbom_components.\"raw\",
                public.\"BDU\".\"raw\"
            FROM
                public.sbom_components
                INNER JOIN public.components ON public.sbom_components.name = public.components.name
                INNER JOIN public.\"BDU\" ON public.components.id_bdu = public.\"BDU\".id
            WHERE
                public.sbom_components.\"SBOM_raw\" = $1
                AND (
                    public.sbom_components.version = public.components.only
                    OR (
                        (
                            public.sbom_components.major > public.components.from_major
                            OR (
                                public.sbom_components.major = public.components.from_major
                                AND public.sbom_components.minor > public.components.from_minor
                            )
                            OR (
                                public.sbom_components.major = public.components.from_major
                                AND public.sbom_components.minor = public.components.from_minor
                                AND public.sbom_components.patch >= public.components.from_patch
                            )
                        )
                        AND (
                            (
                                public.components.inclusive
                                AND (
                                    public.sbom_components.major < public.components.to_major
                                    OR (
                                        public.sbom_components.major <= public.components.to_major
                                        AND public.sbom_components.minor < public.components.to_minor
                                    )
                                    OR (
                                        public.sbom_components.major <= public.components.to_major
                                        AND public.sbom_components.minor <= public.components.to_minor
                                        AND public.sbom_components.patch < public.components.to_patch
                                    )
                                    OR (
                                        public.sbom_components.major = public.components.to_major
                                        AND public.sbom_components.minor = public.components.to_minor
                                        AND public.sbom_components.patch = public.components.to_patch
                                    )
                                )
                            )
                            OR (
                                NOT public.components.inclusive
                                AND (
                                    public.sbom_components.major < public.components.to_major
                                    OR (
                                        public.sbom_components.major <= public.components.to_major
                                        AND public.sbom_components.minor < public.components.to_minor
                                    )
                                    OR (
                                        public.sbom_components.major <= public.components.to_major
                                        AND public.sbom_components.minor <= public.components.to_minor
                                        AND public.sbom_components.patch < public.components.to_patch
                                    )
                                )
                            )
                        )
                    )
                )
            ORDER BY
                public.sbom_components.name ASC,
                public.sbom_components.version ASC;";
        }
        let row = self.client
            .query(query, &[&id]).await
            .expect("Error SELECT public.sbom_components.\"raw\"");

        let mut bugs = Vec::<Bugs>::new();
        for r in row {
            let c = r.get::<_, Json<sbom5::Component>>(0).0;
            let v = r.get::<_, Json<bdu::Component>>(1).0;
            bugs.push(Bugs {
                component: c,
                vuln: v,
            });
        }
        info!("Found {} bugs!", bugs.len());
        if bugs.len() > 0 {
            for bug in &bugs {
                trace!("Bugs: {:?}", &bug);
            }
        } else {
            trace!("Bugs not found =(");
        }
        Ok(bugs)
    }

    #[allow(dead_code)]
    /// Обновление Базы данных БДУ.
    /// Необходимо чтобы в системе стоял *wget*.
    /// Не поддерживается Windows
    pub async fn update(&self) -> Result<(), String> {
        let tmp_dir = TempDir::new("BDUParser").expect("Не могу создать временную папку");
        let path = tmp_dir.path();
        info!("Temporary directory created at: {:?}", path);
        let file_path = path.join("vull.xlsx");
        let output = if cfg!(target_os = "windows") {
            error!("Carga doesn`t support windows yet!");
            Command::new("cmd")
                .args(["/C", "Windows doesn`t support yet"])
                .output()
                .expect("failed to execute process");
            return Err("Windows platform doesn`t support yet".to_string());
        } else {
            debug!("Start load BDU xlsx");
            Command::new("wget")
                .arg("--no-check-certificate")
                .arg("https://bdu.fstec.ru/files/documents/vullist.xlsx")
                .arg("-O")
                .arg(&file_path)
                .output()
                .expect("failed to execute process")
        };
        if output.status.success() {
            let bdu_components = xlsx_parser(&file_path, &String::from("Уязвимости"));
            trace!("Deleting vull.xlsx");
            fs::remove_file(file_path).expect("Error delete vull.xlsx");
            let _ = tmp_dir.close();
            trace!("Deleted vull.xlsx");
            if let Some(components) = bdu_components {
                return self.upload(&components).await;
            } else {
                error!("Faild to parse xlsx BDU");
                return Err("Faild to parse xlsx BDU".to_string());
            }
        } else {
            let _ = tmp_dir.close();
            let res = format!(
                "Get BDU database error: Message: {} Status: {}",
                String::from_utf8(output.stdout).expect("pizdec conver"),
                output.status
            );
            error!("{}", &res);
            return Err(res);
        }
    }
    
    #[allow(dead_code)]
    /// Поиск уязвимостей в sbom файле.
    /// Работает только на Linux. Для работы требуется cyclonedx-linux-x64 в системе для работы.
    /// При загрузке файла, происходит попытка сконвертировать файл в sbom v1.5 json для общей работы.
    /// Сохраняется только удачно сконвертированный sbom.
    ///
    /// # Arguments
    ///
    /// * `foo` - Путь до sbom файла.
    /// * `full` - Найти все совпадения по именам, игнорируя версии.
    ///
    /// # Todo
    ///
    /// Хранить ли сырой пришедший файл?
    pub async fn find(&self, foo: &String, full: bool) -> Result<Vec<Bugs>, String> {
        let output = if cfg!(target_os = "windows") {
            error!("Carga doesn`t support windows.");
            Command::new("cmd")
                .args(["/C", "Windows doesn`t support yet"])
                .output()
                .expect("failed to execute process");
            return Err("Windows platform doesn`t support yet".to_string());
        } else {
            process_file(foo).expect("Ошибка удаления лишних хэшей");
            debug!("Start sbom converted!");
            Command::new("cyclonedx") // TODO: change ? ./cyclonedx-linux-x64
                .arg("convert")
                .args(["--input-file", foo, "--output-format", "json", "--output-version", "v1_5"])
                .output()
                .expect("failed to execute process")
        };
        let sbom: sbom5::Root;
        let mut _id = 0;
        if output.status.success() {
            let cin = &String::from_utf8(output.stdout).expect("pizdec conver");
            let ans = self.client
                .query(
                    "
            INSERT INTO public.\"SBOM_raw\" (sbom) VALUES ($1) RETURNING id;
            ",
                    &[&json!(&cin)]
                ).await
                .expect("Error insert into SBOM_raw");
            _id = ans[0].get::<_, i32>(0);
            sbom = serde_json::from_str::<sbom5::Root>(&cin).expect("Bad json");
        } else {
            let ret = format!(
                "Convert Error: Message: {} Status: {}",
                String::from_utf8(output.stdout).expect("pizdec conver"),
                output.status
            );
            error!("{}", &ret);
            return Err(ret);
        }

        if let Some(sbom_component) = &sbom.components {
            let mut count = 0;
            let re = Regex::new(
                r"(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)|(?<major_2>\d+)\.(?<minor_2>\d+)|(?<major_3>\d+)"
            ).expect("Error regex");
            let mut rows = Vec::new();
            count = self.find_components_recursive(sbom_component, &re, &_id, &mut rows);
            for (name, version, major, minor, patch, sbom_id, raw_json) in rows {
                if
                    self.client
                        .execute(
                            "INSERT INTO public.sbom_components (name, version, major, minor, patch, \"SBOM_raw\", \"raw\") VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (name, version, \"SBOM_raw\") DO NOTHING",
                            &[
                                &name,
                                &version,
                                &Some(major),
                                &Some(minor),
                                &Some(patch),
                                &sbom_id,
                                &raw_json,
                            ]
                        ).await
                        .expect("Error INSERT INTO public.sbom_components") > 0
                {
                    count += 1;
                }
            }
            info!("[Info] Add {}/{} sbom components.", count, sbom_component.len());
        } else {
            return Err("No one sbom components".to_string());
        }
        self.find_bug_bd_one_query(_id, full).await
    }

    fn find_components_recursive<'a>(
        &'a self,
        components: &'a Vec<sbom5::Component>,
        re: &Regex,
        _id: &'a i32,
        out: &mut Vec<(&'a str, Option<&'a String>, i32, i32, i32, i32, serde_json::Value)>
    ) -> i32 {
        let mut count = 0;
        for component in components {
            let major = {
                let mut ret = 0_i32;
                if let Some(ver) = &component.version {
                    let names = ["major", "major_2", "major_3"];
                    if let Some(caps) = re.captures(&ver) {
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
                ret
            };
            let minor = {
                let mut ret = 0_i32;
                if let Some(ver) = &component.version {
                    let names = ["minor", "minor_2"];
                    if let Some(caps) = re.captures(&ver) {
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
                ret
            };
            let ver = {
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
                ret
            };
            out.push((
                &component.name,
                component.version.as_ref(),
                major,
                minor,
                ver,
                *_id,
                json!(component),
            ));
            if let Some(c) = &component.components {
                count += self.find_components_recursive(&c, re, _id, out);
            }
        }
        count
    }

    #[allow(dead_code)]
    async fn upload(&self, components: &Vec<Component>) -> Result<(), String> {
        self.client
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
            ).await
            .expect("Error batch_execute");
        self.client
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
                    PRIMARY KEY (id),
                    CONSTRAINT unique_component_key UNIQUE (name, version, \"SBOM_raw\")
                );
                
                ALTER TABLE IF EXISTS public.sbom_components
                    ADD FOREIGN KEY (\"SBOM_raw\")
                    REFERENCES public.\"SBOM_raw\" (id) MATCH SIMPLE
                    ON UPDATE NO ACTION
                    ON DELETE NO ACTION
                    NOT VALID;
                
                END;"
            ).await
            .expect("Error create components database");
        let re = Regex::new(
            r"^(?<major_full>[[:digit:]]+)\.(?<minor_full>[[:digit:]]+)\.(?<patch_full>[[:digit:]]+)|^(?<major_sep>[[:digit:]]+)\.(?<minor_sep>[[:digit:]]+)|^(?<major_only>[[:digit:]]+)"
        ).unwrap();
        let mut counter = 0;
        for component in components {
            let _k = self.client
                .query(
                    "SELECT public.\"BDU\".id FROM public.\"BDU\" WHERE public.\"BDU\".id = $1 LIMIT 1",
                    &[&component.id]
                ).await
                .expect("pizdec query");
            if _k.len() > 0 {
                trace!("Component {} exist!", &component.id);
            } else {
                counter += 1;
                trace!("Add Component {}) {}!", counter, &component.id);
                // TODO: Настроить правильные поля, к примеру время как время
                let _ = self.client
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
                    ).await
                    .expect("pizdec");
                let versions = &component.versions;
                {
                    if versions.len() > 0 {
                        for version in versions {
                            let _ = self.client
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
                                        &version.name,
                                        &version.from,
                                        &version.to,
                                        &version.only,
                                        &version.inclusive,
                                        &({
                                            let mut ret = 0_i32;
                                            if let Some(from) = &version.from {
                                                let names = [
                                                    "major_full",
                                                    "major_sep",
                                                    "major_only",
                                                ];
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
                                            ret
                                        }),
                                        &({
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
                                            ret
                                        }),
                                        &({
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
                                            ret
                                        }),
                                        &({
                                            let mut ret = 0_i32;
                                            if let Some(to) = &version.to {
                                                let names = [
                                                    "major_full",
                                                    "major_sep",
                                                    "major_only",
                                                ];
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
                                            ret
                                        }),
                                        &({
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
                                            ret
                                        }),
                                        &({
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
                                            ret
                                        }),
                                        &component.id,
                                    ]
                                ).await
                                .expect("pizdec");
                        }
                    } else {
                        if let Some(names) = &component.name {
                            for name in names {
                                let _ = self.client
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
                                    ).await
                                    .expect("pizdec");
                            }
                        }
                    }
                }
                if let Some(platforms) = &component.platforms {
                    for platform in platforms {
                        let pl = self.client
                            .query(
                                "SELECT public.platform.pkey FROM public.platform WHERE ((name = $1) AND (version = $2)) LIMIT 1",
                                &[&platform.name, &platform.version]
                            ).await
                            .expect("pizdec");
                        if pl.len() > 0 {
                            for r in pl {
                                // TODO: по сути оно не нужно, так как не может быть иначе
                                let _id: i32 = r.get(0);
                                let _ = self.client
                                    .execute(
                                        "INSERT INTO public.\"BDU_platform\" (
                                            \"bdu_id\", 
                                            platform
                                        ) VALUES ($1, $2)",
                                        &[&component.id, &_id]
                                    ).await
                                    .expect("pizdec");
                            }
                            continue;
                        }
                        let pl = self.client
                            .query(
                                "INSERT INTO public.platform (name, version) VALUES ($1, $2) returning pkey",
                                &[&platform.name, &platform.version]
                            ).await
                            .expect("pizdec platform");
                        for r in pl {
                            // TODO: по сути оно не нужно, так как не может быть иначе
                            let _id: i32 = r.get(0);
                            let _ = self.client
                                .execute(
                                    "INSERT INTO public.\"BDU_platform\" (\"bdu_id\", platform) VALUES ($1, $2)",
                                    &[&component.id, &_id]
                                ).await
                                .expect("pizdec");
                        }
                    }
                }
            }
        }
        info!("Add {}/{} BDU.", counter, components.len());
        Ok(())
    }
}

use serde_json::Value;
use std::error::Error;

fn remove_hashes_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("hashes");
            for v in map.values_mut() {
                remove_hashes_fields(v);
            }
        },
        Value::Array(arr) => {
            for v in arr {
                remove_hashes_fields(v);
            }
        },
        _ => {}
    }
}

fn process_file(full_path: &str) -> Result<(), Box<dyn Error>> {
    // Читаем файл как строку
    let content = fs::read_to_string(full_path)?;

    // Пытаемся распарсить как JSON
    let mut json_value: Value = serde_json::from_str(&content)?;

    // Удаляем все поля "hashes"
    remove_hashes_fields(&mut json_value);

    // Записываем обратно в файл (если нужно)
    fs::write(full_path, serde_json::to_string_pretty(&json_value)?)?;

    Ok(())
}