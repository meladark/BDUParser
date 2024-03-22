// extern crate postgres;

use postgres::{Client, NoTls};
struct Person {
    id: i32,
    name: String,
    data: Option<Vec<u8>>
}
// postgresql://bdu:bdu@localhost:5433/bdu user=bdu password=bdu dbname=bdu host=localhost port=64111 connect_timeout=10 keepalives=0
pub fn connect() {
    let mut client = Client::connect("postgresql://bdu:bdu@localhost:5433/bdu", NoTls).expect("Error connection!");

client.batch_execute("
    CREATE TABLE person (
        id      SERIAL PRIMARY KEY,
        name    TEXT NOT NULL,
        data    BYTEA
    )
").expect("Error batch_execute");

let name = "Ferris";
let data = None::<&[u8]>;
client.execute(
    "INSERT INTO person (name, data) VALUES ($1, $2)",
    &[&name, &data],
).expect("Error execute");

for row in client.query("SELECT id, name, data FROM person", &[]).expect("Error query") {
    let id: i32 = row.get(0);
    let name: &str = row.get(1);
    let data: Option<&[u8]> = row.get(2);

    println!("found person: {} {} {:?}", id, name, data);
}
}
