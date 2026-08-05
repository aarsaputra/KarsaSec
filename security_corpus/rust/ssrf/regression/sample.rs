use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::var("TARGET_URL")?;
    let response = ureq::get(&url).call()?;
    println!("{}", response.into_string()?);
    Ok(())
}
