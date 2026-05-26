mod collector;
mod commands;
mod forwarder;
mod service;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use dnslog_core::config::StorageFormat;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "dnslog-agent")]
#[command(about = "Lightweight local DNS logging agent for defensive telemetry")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Run {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
    },
    Interfaces,
    ValidateConfig {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Once {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = 30)]
        seconds: u64,
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
    },
    ServiceTemplate {
        #[arg(long)]
        target: ServiceTarget,
    },
    ConfigureHost {
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum ServiceTarget {
    Linux,
    Macos,
    Windows,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Csv,
}

impl From<OutputFormat> for StorageFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Json => Self::Json,
            OutputFormat::Csv => Self::Csv,
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dnslog_agent=info,dnslog_capture=info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Run { config, format } => {
            commands::run(config.as_deref(), None, format.map(Into::into))
        }
        Commands::Interfaces => commands::interfaces(),
        Commands::ValidateConfig { config } => commands::validate_config(config.as_deref()),
        Commands::Once {
            config,
            seconds,
            format,
        } => commands::run(
            config.as_deref(),
            Some(std::time::Duration::from_secs(seconds)),
            format.map(Into::into),
        ),
        Commands::ServiceTemplate { target } => {
            let target = match target {
                ServiceTarget::Linux => service::ServiceTarget::Linux,
                ServiceTarget::Macos => service::ServiceTarget::Macos,
                ServiceTarget::Windows => service::ServiceTarget::Windows,
            };
            println!("{}", service::template(target));
            Ok(())
        }
        Commands::ConfigureHost { output } => commands::configure_host(&output),
    }
}
