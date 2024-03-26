use std::ops::ControlFlow;

// extern crate postgres;
// use include_postgres_sql::{include_sql, impl_sql};
use postgres::{fallible_iterator::Cloned, Client, NoTls};
use crate::bdu::{self, Component, Platform, Version, CWE};



// include_sql!("../bdu_sql/same.sql");

// postgresql://bdu:bdu@localhost:5433/bdu user=bdu password=bdu dbname=bdu host=localhost port=64111 connect_timeout=10 keepalives=0 components: &Vec<Component>
pub fn connect_create(components: &Vec<Component>) {
    let mut client = Client::connect("postgresql://bdu:bdu@localhost:5433/bdu", NoTls)
        .expect("Error connection!");

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

    END;
",
        )
        .expect("Error batch_execute");

    // let name = "Ferris";
    // let data = None::<&[u8]>;
    // client.execute(
    //     "INSERT INTO person (name, data) VALUES ($1, $2)",
    //     &[&name, &data],
    // ).expect("Error execute");
    let component = Component {
        id: "BDU:2023-03670".to_string(),
        name_vuln: Some("Уязвимость реализации протокола Bluetooth Classic спецификации Bluetooth Core Specification, позволяющая нарушителю раскрыть защищаемую информацию".to_string()),
        desc_vuln: Some("Уязвимость функции mctp_unregister() ядра операционных систем Linux связана с использованием памяти после ее освобождения при обработке объекта mdev->addrs. Эксплуатация уязвимости может позволить нарушителю вызвать отказ в обслуживании".to_string()),
        vendors: Some([
            "ООО «РусБИТех-Астра»".to_string(),
            "ООО «Ред Софт»".to_string(),
            "Сообщество свободного программного обеспечения".to_string()
          ].to_vec()),
        name: Some([
            "Astra Linux Special Edition (запись в едином реестре российских программ №369)".to_string(),
            "РЕД ОС (запись в едином реестре российских программ №3751)".to_string(),
            "Linux".to_string()
          ].to_vec()),
        v_test: Some([].to_vec()),
        versions: Some([
            Version {
              from: Some("".to_string()),
              to: Some("".to_string()),
              only: Some("7.3".to_string()),
              inclusive: false,
              name: "РЕД ОС".to_string()
            },
            Version {
              from: Some("".to_string()),
              to: Some("".to_string()),
              only: Some("1.7".to_string()),
              inclusive: false,
              name: "Astra Linux Special Edition".to_string()
            },
            Version {
              from: Some("5.15".to_string()),
              to: Some("5.17.5".to_string()),
              only: Some("".to_string()),
              inclusive: true,
              name: "Linux".to_string()
            }
          ].to_vec()),
        software_types: Some(["Операционная система".to_string()].to_vec()),
        v_platforms: Some([].to_vec()),
        platforms: Some([
            Platform {
              name: Some("Astra Linux Special Edition".to_string()),
              version: Some("1.6 «Смоленск»; запись в едином реестре российских программ №369".to_string())
            },
            Platform {
              name: Some("РЕД ОС".to_string()),
              version: Some("7.3; запись в едином реестре российских программ №3751".to_string())
            },
            Platform {
              name: Some("Astra Linux Special Edition".to_string()),
              version: Some("1.7; запись в едином реестре российских программ №369".to_string())
            },
            Platform { name: Some("Linux".to_string()), version: Some("от 5.15 до 5.17.5 включительно".to_string()) }
          ].to_vec()),
        class_vuln: Some("Уязвимость кода".to_string()),
        date: Some("22.04.2022".to_string()),
        cvss2: Some("AV:L/AC:L/Au:S/C:N/I:N/A:C".to_string()),
        cvss3: Some("AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H".to_string()),
        severity: Some("Средний уровень опасности (базовая оценка CVSS 2.0 составляет 4,6)\nСредний уровень опасности (базовая оценка CVSS 3.0 составляет 5,5)".to_string()),
        possible_fix: Some("Использование рекомендаций:\nhttps://kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.17.6\n\nДля РедОС: http://repo.red-soft.ru/redos/7.3c/x86_64/updates/\n\nДля ОС Astra Linux Special Edition 1.7:\nобновить пакет linux-5.15 до 5.15.0-83.astra1+ci14 или более высокой версии, используя рекомендации производителя: https://wiki.astralinux.ru/astra-linux-se17-bulletin-2023-1023SE17\n\nДля Astra Linux 1.6 «Смоленск»:\nобновить пакет linux-5.15 до 5.15.0-83.astra1+ci36 или более высокой версии, используя рекомендации производителя: https://wiki.astralinux.ru/astra-linux-se16-bulletin-20231214SE16".to_string()),
        status_vuln: Some("Подтверждена производителем".to_string()),
        exploit: Some("Существует в открытом доступе".to_string()),
        fix: Some("Уязвимость устранена".to_string()),
        source_sites: Some([
            "https://www.linuxkernelcves.com/cves/CVE-2023-3439".to_string(),
            "https://access.redhat.com/security/cve/CVE-2023-3439".to_string(),
            "https://kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.17.6".to_string(),
            "http://www.openwall.com/lists/oss-security/2023/07/02/1 ".to_string(),
            "https://bugzilla.redhat.com/show_bug.cgi?id=2217915".to_string(),
            "http://repo.red-soft.ru/redos/7.3c/x86_64/updates/".to_string(),
            "https://wiki.astralinux.ru/astra-linux-se17-bulletin-2023-1023SE17".to_string(),
            "https://wiki.astralinux.ru/astra-linux-se16-bulletin-20231214SE16".to_string()
          ].to_vec()),
        id_another_system: Some(["CVE-2023-3439".to_string()].to_vec()),
        info: Some("".to_string()),
        conn_is: Some(0),
        cwe: CWE {
            info: Some([
                "Одновременное выполнение с использованием общего ресурса с неправильной синхронизацией («Ситуация гонки»)".to_string(),
                "Использование после освобождения".to_string()
              ].to_vec()),
            id: Some(["CWE-362".to_string(), "CWE-416".to_string()].to_vec())
        },
    };
    
    for component in components{
        let _k = client.query("SELECT public.\"BDU\".id FROM public.\"BDU\" WHERE public.\"BDU\".id = $1 LIMIT 1", &[&component.id]).expect("pizdec query");
        if _k.len() > 0 {
            //print!("Exist!")
        }else{
            //print!("Not Exist!");
            // TODO: Настроить правильные поля, к примеру время как время
            let _ = client.execute("INSERT INTO public.\"BDU\" (id, name, \"desc\", vendors, software_types, class, date, cvss2, cvss3, severity, possible_fix, status, exploit, fix, source_sites, id_another_system, info, conn_is, \"CWE_info\", \"CWE_id\") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)", &[
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
                &component.cwe.id
            ]).expect("pizdec");
            if let Some(platforms) = &component.platforms{
                for platform in platforms {
                    let pl = client.query("SELECT public.platform.pkey FROM public.platform WHERE ((name = $1) AND (version = $2)) LIMIT 1", &[&platform.name, &platform.version]).expect("pizdec");
                    if pl.len() > 0 {
                        for r in pl { // TODO: по сути оно не нужно, так как не может быть иначе
                            let _id: i32 = r.get(0);
                            let _ = client.execute("INSERT INTO public.\"BDU_platform\" (\"bdu_id\", platform) VALUES ($1, $2)", &[&component.id, &_id]).expect("pizdec");
                        }
                        continue;
                    }
                    let pl = client.query("INSERT INTO public.platform (name, version) VALUES ($1, $2) returning pkey", &[&platform.name, &platform.version]).expect("pizdec platform");
                    for r in pl { // TODO: по сути оно не нужно, так как не может быть иначе
                        let _id: i32 = r.get(0);
                        let _ = client.execute("INSERT INTO public.\"BDU_platform\" (\"bdu_id\", platform) VALUES ($1, $2)", &[&component.id, &_id]).expect("pizdec");
                    }
                }
            }   
        }
    }
    for row in client.query("SELECT public.\"BDU\".id FROM public.\"BDU\" INNER JOIN public.components ON public.\"BDU\".id = components.\"id_bdu\" WHERE public.components.name = 'Bluetooth Core Specification';", &[]).expect("Error query") {
    let id: &str = row.get(0);
    println!("found person: {}", id);
}
}
