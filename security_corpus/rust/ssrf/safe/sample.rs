fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "https://example.com";
    let response = reqwest::blocking::get(url)?;
    println!("{}", response.text()?);
    Ok(())
}
