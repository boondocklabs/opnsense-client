use opnsense_client::{Certificate, Client};
use serde_json::Value;

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
    let mut args = std::env::args().skip(1);
    let kind = args.next().unwrap_or_else(|| "cpu".into());
    let count = args
        .next()
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(usize::MAX);
    let mut stream = match kind.as_str() {
        "cpu" => client.cpu_usage_stream().await?,
        "traffic" => client.traffic_stream(1).await?,
        _ => return Err("usage: stream [cpu|traffic] [sample-count]".into()),
    };
    for _ in 0..count {
        let Some(sample) = stream.next_json::<Value>().await? else {
            break;
        };
        println!("{}", serde_json::to_string(&sample)?);
    }
    Ok(())
}
