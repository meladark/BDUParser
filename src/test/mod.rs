#[cfg(test)]
mod test {
    use std::time::Instant;
    use env_logger;
    use log::info;
    use crate::{ bd::BD, get_pdf };

    #[tokio::test]
    async fn test_postgres() {
        env_logger::init();
        info!("Start test_postgres!!!!!");
        let t = BD::default().await.expect("Error default");
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

    #[tokio::test]
    async fn test_latex() {
        let t = BD::default().await.expect("Error connect");
        match t.find(&"extra/bom.1.5.json".to_string(), false).await {
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
    async fn test_typst(){

    }
}
