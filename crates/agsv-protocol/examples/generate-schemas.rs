//! Regenerates committed protocol schemas from Rust source types.

use agsv_protocol::{domain_schema, wire_schema};
use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let output = env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from("schemas"), PathBuf::from);
    fs::create_dir_all(&output)?;
    write_schema(output.join("agsv-wire-v0.1.schema.json"), &wire_schema())?;
    write_schema(
        output.join("agsv-domain-v0.1.schema.json"),
        &domain_schema(),
    )?;
    Ok(())
}

fn write_schema(path: PathBuf, schema: &schemars::Schema) -> Result<(), Box<dyn Error>> {
    let mut json = serde_json::to_string_pretty(&schema)?;
    json.push('\n');
    fs::write(path, json)?;
    Ok(())
}
