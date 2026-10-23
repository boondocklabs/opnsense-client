use std::time::Duration;

use opnsense_client::{
    Certificate, Client,
    insight::{Dataset, TimeRange, TimeSeriesQuery, TopQuery},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|s| s == "--help") {
        println!("usage: insight [interface-device|all] [hours=1] [csv-output-path]");
        return Ok(());
    }
    if args.len() > 3 {
        return Err("usage: insight [interface-device|all] [hours=1] [csv-output-path]".into());
    }
    let device = args.first().filter(|s| s.as_str() != "all");
    let hours = args
        .get(1)
        .map(|s| s.parse::<u64>())
        .transpose()?
        .unwrap_or(1);
    let seconds = hours.checked_mul(3600).ok_or("hours value is too large")?;
    let range = TimeRange::last(Duration::from_secs(seconds))?;
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
    let insight = client.insight();
    let metadata = insight.metadata().await?;
    let interfaces = insight.interfaces().await?;
    println!("Interfaces: {}", serde_json::to_string(&interfaces)?);
    println!("Last capture sync (Unix seconds): {:?}", metadata.last_sync);
    if let Some(device) = device
        && !interfaces.contains_key(device)
    {
        return Err(
            format!("unknown interface device {device}; use one of the names above").into(),
        );
    }
    let dataset = Dataset::InterfaceTotals;
    let resolutions = &metadata.aggregators.get(dataset.as_str())
        .ok_or("No Insight datasets found; enable NetFlow Capture local and allow time to collect data")?.resolutions;
    // Use the UI's conventional retention tiers; confirm availability on this firewall.
    let preferred = match hours {
        0..=2 => 30,
        3..=8 => 300,
        9..=168 => 3600,
        _ => 86400,
    };
    let resolution = resolutions
        .iter()
        .copied()
        .filter(|r| *r >= preferred)
        .min()
        .ok_or("No suitable retained resolution for this time window")?;
    let series = insight
        .time_series(&TimeSeriesQuery::new(dataset, range, resolution)?)
        .await?;
    let point_count: usize = series.iter().map(|s| s.values.len()).sum();
    println!(
        "Interface history: {} series, {point_count} points, {resolution}s buckets (bits/s)",
        series.len()
    );

    for (label, mut query) in [
        ("Interface totals", TopQuery::interfaces(range)),
        ("Top source hosts", TopQuery::sources(range).limit(10)?),
        ("Top destination ports", TopQuery::ports(range).limit(10)?),
        ("Detailed flow groups", TopQuery::details(range).limit(5)?),
    ] {
        if let Some(device) = device {
            query = query.interface(device)?;
        }
        let rows = insight.top(&query).await?;
        println!("{label} (bytes): {}", serde_json::to_string(&rows)?);
    }
    if let Some(path) = args.get(2) {
        // Export returns the entire dataset, without the top-report interface filter.
        let csv = insight.export_csv(dataset, range, resolution).await?;
        std::fs::write(path, csv)?;
        println!("Exported all-interface CSV to {path}");
    }
    Ok(())
}
