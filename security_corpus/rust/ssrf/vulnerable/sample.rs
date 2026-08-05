use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args().nth(1).unwrap_or_else(|| "http://example.com".to_string());
    let response = reqwest::blocking::get(&url)?;
    println!("{}", response.text()?);
    Ok(())
}
