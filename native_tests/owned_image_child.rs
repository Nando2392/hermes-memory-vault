use std::io::{self, Write};
use std::thread;
use std::time::Duration;

fn main() {
    // Bound orphan lifetime even if the disposable controller is interrupted.
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(30));
        std::process::exit(124);
    });
    println!("{}", env!("IMAGE_LABEL"));
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}
