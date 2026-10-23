use opnsense_client::{Certificate, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(error) = dotenvy::dotenv()
        && !error.not_found()
    {
        return Err(error.into());
    }
    let mut builder = Client::builder(
        std::env::var("OPNSENSE_URL")?,
        std::env::var("OPNSENSE_API_KEY")?,
        std::env::var("OPNSENSE_API_SECRET")?,
    );
    if let Some(path) = std::env::var_os("OPNSENSE_CA_CERT") {
        builder = builder.add_root_certificate(Certificate::from_pem(&std::fs::read(path)?)?);
    }
    let client = builder.build()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&client.firmware_info().await?)?
    );
    Ok(())
}
