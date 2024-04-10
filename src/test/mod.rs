#[cfg(test)]
mod test {
    use std::{ fs, path::Path, time::Instant };

    use crate::bd::BD;

    #[tokio::test]
    async fn test_postgres() {
        let t = BD::default().await.expect("Error default");
        let k = t.update().await;
        match k {
            Ok(_) => println!("Well done"),
            Err(err) => println!("{}", err),
        }
    }
    #[tokio::test]
    async fn test_find_bug_bd_one_query() {
        let start = Instant::now();
        let t = BD::default().await.expect("Error connect");
        match t.find(&"extra/bom.1.5.json".to_string()).await {
            Ok(k) =>
                for i in k {
                    println!("{} {}", i.component.name, i.vuln.id);
                }
            Err(err) => println!("[Error] {}", err),
        }
        let duration = start.elapsed();
        println!("Time elapsed in find_bug_bd_one_query() is: {:?}", duration);
    }
}
