use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand, ValueEnum};
use supplygraph::{
    EvidencePaths, ExplainReport, GraphReport, SupplyError, explain, inspect, render_explain_text,
    render_graph_text, render_json,
};

#[derive(Debug, Parser)]
#[command(
    name = "supplygraph",
    version,
    about = "Join local Rust dependency supply-chain evidence"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Explain {
        package: String,
        #[arg(long, default_value = "Cargo.lock")]
        lockfile: PathBuf,
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        #[arg(long)]
        advisories: Option<PathBuf>,
        #[arg(long)]
        audits: Option<PathBuf>,
        #[arg(long)]
        licenses: Option<PathBuf>,
        #[arg(long)]
        binary: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    Inspect {
        lockfile: PathBuf,
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        #[arg(long)]
        advisories: Option<PathBuf>,
        #[arg(long)]
        audits: Option<PathBuf>,
        #[arg(long)]
        licenses: Option<PathBuf>,
        #[arg(long)]
        binary: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    Export {
        #[arg(long, default_value = "Cargo.lock")]
        lockfile: PathBuf,
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        #[arg(long)]
        advisories: Option<PathBuf>,
        #[arg(long)]
        audits: Option<PathBuf>,
        #[arg(long)]
        licenses: Option<PathBuf>,
        #[arg(long)]
        binary: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Explain {
            package,
            lockfile,
            manifest_path,
            advisories,
            audits,
            licenses,
            binary,
            format,
        } => match explain(
            &lockfile,
            &package,
            manifest_path.as_deref(),
            &EvidencePaths {
                advisories,
                audits,
                licenses,
                binary,
            },
        ) {
            Ok(report) => finish_explain(&report, format),
            Err(error) => finish_error(error),
        },
        Command::Inspect {
            lockfile,
            manifest_path,
            advisories,
            audits,
            licenses,
            binary,
            format,
        }
        | Command::Export {
            lockfile,
            manifest_path,
            advisories,
            audits,
            licenses,
            binary,
            format,
        } => match inspect(
            &lockfile,
            manifest_path.as_deref(),
            &EvidencePaths {
                advisories,
                audits,
                licenses,
                binary,
            },
        ) {
            Ok(report) => finish_graph(&report, format),
            Err(error) => finish_error(error),
        },
    }
}

fn finish_graph(report: &GraphReport, format: OutputFormat) -> ExitCode {
    match print_value(report, format, render_graph_text) {
        Ok(()) => ExitCode::from(report.exit_code() as u8),
        Err(error) => finish_render_error(error),
    }
}

fn finish_explain(report: &ExplainReport, format: OutputFormat) -> ExitCode {
    match print_value(report, format, render_explain_text) {
        Ok(()) => ExitCode::from(report.exit_code() as u8),
        Err(error) => finish_render_error(error),
    }
}

fn print_value<T: serde::Serialize>(
    value: &T,
    format: OutputFormat,
    render_text: impl FnOnce(&T) -> String,
) -> serde_json::Result<()> {
    match format {
        OutputFormat::Text => {
            print!("{}", render_text(value));
            Ok(())
        }
        OutputFormat::Json => {
            println!("{}", render_json(value)?);
            Ok(())
        }
    }
}

fn finish_error(error: SupplyError) -> ExitCode {
    eprintln!("supplygraph: {error}");
    ExitCode::from(3)
}

fn finish_render_error(error: serde_json::Error) -> ExitCode {
    eprintln!("supplygraph: could not render report: {error}");
    ExitCode::from(3)
}
