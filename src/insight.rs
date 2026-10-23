//! Typed access to Insight's historical NetFlow data.
//!
//! Enable NetFlow's **Capture local** option and grant the API user Insight
//! reporting access. Requests use UTC Unix seconds; time-series points returned
//! by OPNsense use Unix milliseconds. Empty reports are valid when no flows
//! were recorded. Consult [`Insight::metadata`] for available resolutions.
//!
//! ```no_run
//! use std::time::Duration;
//! use opnsense_client::{Client, insight::{TimeRange, TopQuery}};
//!
//! # async fn example(client: &Client) -> opnsense_client::Result<()> {
//! let range = TimeRange::last(Duration::from_secs(3600))?;
//! let query = TopQuery::sources(range).limit(10)?.interface("igc0")?;
//! let hosts = client.insight().top(&query).await?;
//! for host in hosts {
//!     println!("{:?}: {} bytes", host.source_address, host.total);
//! }
//! # Ok(())
//! # }
//! ```

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{Client, Error, Result};

/// An ordered, nonempty interval in UTC Unix seconds. The server treats the
/// end as exclusive, and may round the start down to an aggregation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeRange {
    start: u64,
    end: u64,
}

impl TimeRange {
    pub fn new(start: u64, end: u64) -> Result<Self> {
        if start >= end || end > i64::MAX as u64 {
            return Err(Error::Configuration(
                "Insight range must have start < end, within signed Unix seconds",
            ));
        }
        Ok(Self { start, end })
    }

    /// A range ending now. Subsecond-only windows are rejected.
    pub fn last(duration: Duration) -> Result<Self> {
        let end = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Configuration("system clock is before the Unix epoch"))?
            .as_secs();
        let start = end
            .checked_sub(duration.as_secs())
            .ok_or(Error::Configuration(
                "Insight duration exceeds time since the Unix epoch",
            ))?;
        Self::new(start, end)
    }

    pub fn start(&self) -> u64 {
        self.start
    }
    pub fn end(&self) -> u64 {
        self.end
    }
}

/// OPNsense's case-sensitive aggregation providers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dataset {
    InterfaceTotals,
    SourceAddressTotals,
    DestinationPortTotals,
    SourceAddressDetails,
}

impl Dataset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InterfaceTotals => "FlowInterfaceTotals",
            Self::SourceAddressTotals => "FlowSourceAddrTotals",
            Self::DestinationPortTotals => "FlowDstPortTotals",
            Self::SourceAddressDetails => "FlowSourceAddrDetails",
        }
    }

    pub fn fields(self) -> &'static [Field] {
        use Field::*;
        match self {
            Self::InterfaceTotals => &[Interface, Direction],
            Self::SourceAddressTotals => &[Interface, SourceAddress, Direction],
            Self::DestinationPortTotals => &[Interface, Protocol, DestinationPort],
            Self::SourceAddressDetails => &[
                Interface,
                Direction,
                SourceAddress,
                DestinationAddress,
                ServicePort,
                Protocol,
            ],
        }
    }
}

/// A grouping or filter field. Unsupported dataset/field combinations are rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    Interface,
    Direction,
    SourceAddress,
    DestinationAddress,
    DestinationPort,
    ServicePort,
    Protocol,
}

impl Field {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interface => "if",
            Self::Direction => "direction",
            Self::SourceAddress => "src_addr",
            Self::DestinationAddress => "dst_addr",
            Self::DestinationPort => "dst_port",
            Self::ServicePort => "service_port",
            Self::Protocol => "protocol",
        }
    }
}

/// Values available in historical time series. Byte counts may be fractional
/// because NetFlow attributes a flow across aggregation intervals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Measure {
    Bytes,
    Packets,
    BytesPerSecond,
    BitsPerSecond,
    PacketsPerSecond,
}

impl Measure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "octets",
            Self::Packets => "packets",
            Self::BytesPerSecond => "octets_ps",
            Self::BitsPerSecond => "bps",
            Self::PacketsPerSecond => "packets_ps",
        }
    }
}

/// Ranking and totals queries support counts, rather than rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotalMeasure {
    Bytes,
    Packets,
}

impl TotalMeasure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "octets",
            Self::Packets => "packets",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TimeSeriesQuery {
    dataset: Dataset,
    range: TimeRange,
    resolution: u32,
    measure: Measure,
    fields: Vec<Field>,
}

impl TimeSeriesQuery {
    /// Default: bits per second, grouped by all fields in the dataset.
    /// Resolution is in seconds; use the server's metadata to select one it retains.
    pub fn new(dataset: Dataset, range: TimeRange, resolution_seconds: u32) -> Result<Self> {
        validate_resolution(resolution_seconds)?;
        Ok(Self {
            dataset,
            range,
            resolution: resolution_seconds,
            measure: Measure::BitsPerSecond,
            fields: dataset.fields().to_vec(),
        })
    }

    pub fn measure(mut self, measure: Measure) -> Self {
        self.measure = measure;
        self
    }

    pub fn group_by(mut self, fields: &[Field]) -> Result<Self> {
        validate_fields(self.dataset, fields)?;
        self.fields = fields.to_vec();
        Ok(self)
    }
}

#[derive(Clone, Debug)]
pub struct TopQuery {
    dataset: Dataset,
    range: TimeRange,
    measure: TotalMeasure,
    fields: Vec<Field>,
    filters: BTreeMap<Field, String>,
    limit: u32,
}

impl TopQuery {
    /// Default: bytes, grouped by all dataset fields, with 25 ranked rows.
    /// OPNsense may append one additional row for the remaining traffic.
    pub fn new(dataset: Dataset, range: TimeRange) -> Self {
        Self {
            dataset,
            range,
            measure: TotalMeasure::Bytes,
            fields: dataset.fields().to_vec(),
            filters: BTreeMap::new(),
            limit: 25,
        }
    }

    /// Rank source addresses, combining interfaces and directions unless filtered.
    pub fn sources(range: TimeRange) -> Self {
        Self {
            fields: vec![Field::SourceAddress],
            ..Self::new(Dataset::SourceAddressTotals, range)
        }
    }

    /// Rank destination port/protocol pairs.
    pub fn ports(range: TimeRange) -> Self {
        Self {
            fields: vec![Field::DestinationPort, Field::Protocol],
            ..Self::new(Dataset::DestinationPortTotals, range)
        }
    }

    /// Per-interface and per-direction totals over a time range.
    pub fn interfaces(range: TimeRange) -> Self {
        Self::new(Dataset::InterfaceTotals, range)
    }

    /// Detailed source/destination/service traffic, aggregated over the range.
    pub fn details(range: TimeRange) -> Self {
        Self::new(Dataset::SourceAddressDetails, range)
    }

    pub fn measure(mut self, measure: TotalMeasure) -> Self {
        self.measure = measure;
        self
    }

    pub fn limit(mut self, limit: u32) -> Result<Self> {
        if limit == 0 {
            return Err(Error::Configuration(
                "Insight result limit must be positive",
            ));
        }
        self.limit = limit;
        Ok(self)
    }

    pub fn group_by(mut self, fields: &[Field]) -> Result<Self> {
        validate_fields(self.dataset, fields)?;
        self.fields = fields.to_vec();
        Ok(self)
    }

    /// Filter before ranking. Repeated fields replace their previous filter.
    /// Values are literal tokens (IP addresses, interface names, numbers, or
    /// `in`/`out`); delimiter characters and expressions are rejected.
    pub fn filter(mut self, field: Field, value: impl Into<String>) -> Result<Self> {
        validate_fields(self.dataset, &[field])?;
        let value = value.into();
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        {
            return Err(Error::Configuration(
                "Insight filter must be a nonempty literal token",
            ));
        }
        self.filters.insert(field, value);
        Ok(self)
    }

    /// Use the device name from [`Insight::interfaces`], such as `igc0`, not `WAN`.
    pub fn interface(self, device: impl Into<String>) -> Result<Self> {
        self.filter(Field::Interface, device)
    }
}

/// Dataset availability reported by the firewall. Unknown future providers are retained.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Metadata {
    #[serde(default)]
    pub aggregators: BTreeMap<String, Aggregator>,
    /// UTC Unix seconds, when available.
    #[serde(default)]
    pub last_sync: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Aggregator {
    #[serde(default)]
    pub resolutions: Vec<u32>,
}

/// A point on OPNsense's time axis. JSON wire format is `[timestamp_ms, value]`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(from = "(u64, f64)", into = "(u64, f64)")]
pub struct TimePoint {
    pub timestamp_millis: u64,
    pub value: f64,
}

impl From<(u64, f64)> for TimePoint {
    fn from((timestamp_millis, value): (u64, f64)) -> Self {
        Self {
            timestamp_millis,
            value,
        }
    }
}
impl From<TimePoint> for (u64, f64) {
    fn from(point: TimePoint) -> Self {
        (point.timestamp_millis, point.value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimeSeries {
    pub key: String,
    pub values: Vec<TimePoint>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub direction: Option<String>,
}

/// A ranked/aggregated row. `total` uses the measure selected in the query.
/// OPNsense's final "other" row has empty grouping fields; these become `None`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TopRow {
    pub total: f64,
    #[serde(default, rename = "if", deserialize_with = "optional_text")]
    pub interface: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    pub direction: Option<String>,
    #[serde(default, rename = "src_addr", deserialize_with = "optional_text")]
    pub source_address: Option<String>,
    #[serde(default, rename = "dst_addr", deserialize_with = "optional_text")]
    pub destination_address: Option<String>,
    #[serde(default, rename = "dst_port", deserialize_with = "optional_text")]
    pub destination_port: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    pub service_port: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    pub protocol: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    pub label: Option<String>,
    /// Server-provided time string (or numeric timestamp rendered as text).
    /// No timezone is inferred for naive server strings.
    #[serde(default, deserialize_with = "optional_text")]
    pub last_seen: Option<String>,
}

impl TopRow {
    pub fn is_other(&self) -> bool {
        [
            &self.interface,
            &self.direction,
            &self.source_address,
            &self.destination_address,
            &self.destination_port,
            &self.service_port,
            &self.protocol,
        ]
        .iter()
        .all(|v| v.is_none())
    }
}

/// A borrowed reporting facade sharing the parent client's pool and credentials.
#[derive(Clone, Copy, Debug)]
pub struct Insight<'a> {
    client: &'a Client,
}

impl<'a> Insight<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn metadata(&self) -> Result<Metadata> {
        self.object("get_metadata").await
    }
    /// Device names mapped to display names, e.g. `igc0` -> `WAN`.
    pub async fn interfaces(&self) -> Result<BTreeMap<String, String>> {
        self.object("get_interfaces").await
    }
    pub async fn protocols(&self) -> Result<BTreeMap<String, String>> {
        self.object("get_protocols").await
    }
    pub async fn services(&self) -> Result<BTreeMap<String, String>> {
        self.object("get_services").await
    }

    pub async fn time_series(&self, query: &TimeSeriesQuery) -> Result<Vec<TimeSeries>> {
        let start = query.range.start.to_string();
        let end = query.range.end.to_string();
        let resolution = query.resolution.to_string();
        let fields = field_names(&query.fields);
        self.client
            .get(&[
                "diagnostics",
                "networkinsight",
                "timeserie",
                query.dataset.as_str(),
                query.measure.as_str(),
                &start,
                &end,
                &resolution,
                &fields,
            ])
            .await
    }

    pub async fn top(&self, query: &TopQuery) -> Result<Vec<TopRow>> {
        let start = query.range.start.to_string();
        let end = query.range.end.to_string();
        let limit = query.limit.to_string();
        let fields = field_names(&query.fields);
        let filters = [
            (
                "filter_field",
                query
                    .filters
                    .keys()
                    .map(|f| f.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "filter_value",
                query
                    .filters
                    .values()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ];
        let endpoint = [
            "diagnostics",
            "networkinsight",
            "top",
            query.dataset.as_str(),
            &start,
            &end,
            &fields,
            query.measure.as_str(),
            &limit,
        ];
        if query.filters.is_empty() {
            self.client.get(&endpoint).await
        } else {
            self.client.get_with_query(&endpoint, &filters).await
        }
    }

    /// CSV text returned by OPNsense, bounded by the client's response-size limit.
    pub async fn export_csv(
        &self,
        dataset: Dataset,
        range: TimeRange,
        resolution_seconds: u32,
    ) -> Result<String> {
        validate_resolution(resolution_seconds)?;
        let bytes = self
            .client
            .get_bytes(&[
                "diagnostics",
                "networkinsight",
                "export",
                dataset.as_str(),
                &range.start.to_string(),
                &range.end.to_string(),
                &resolution_seconds.to_string(),
            ])
            .await?;
        Ok(String::from_utf8(bytes)?)
    }

    async fn object<T: DeserializeOwned + Default>(&self, command: &str) -> Result<T> {
        let value: Value = self
            .client
            .get(&["diagnostics", "networkinsight", command])
            .await?;
        // PHP encodes empty associative arrays as [], including disabled Insight.
        if value.as_array().is_some_and(Vec::is_empty) {
            Ok(T::default())
        } else {
            Ok(serde_json::from_value(value)?)
        }
    }
}

fn validate_resolution(seconds: u32) -> Result<()> {
    if seconds == 0 {
        Err(Error::Configuration("Insight resolution must be positive"))
    } else {
        Ok(())
    }
}

fn validate_fields(dataset: Dataset, fields: &[Field]) -> Result<()> {
    if fields.is_empty() || fields.iter().any(|f| !dataset.fields().contains(f)) {
        return Err(Error::Configuration(
            "Insight grouping/filter fields must belong to the dataset and cannot be empty",
        ));
    }
    if fields
        .iter()
        .enumerate()
        .any(|(i, f)| fields[..i].contains(f))
    {
        return Err(Error::Configuration(
            "Insight grouping fields must be unique",
        ));
    }
    Ok(())
}

fn field_names(fields: &[Field]) -> String {
    fields
        .iter()
        .map(|f| f.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn optional_text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    match Value::deserialize(deserializer)? {
        Value::Null => Ok(None),
        Value::String(s) if s.is_empty() => Ok(None),
        Value::String(s) => Ok(Some(s)),
        Value::Number(n) => Ok(Some(n.to_string())),
        _ => Err(serde::de::Error::custom("expected text, number, or null")),
    }
}
