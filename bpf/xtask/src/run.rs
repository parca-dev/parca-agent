use std::{os::unix::process::CommandExt, process::Command};

use anyhow::Context as _;
use structopt::StructOpt;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

#[derive(StructOpt)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[structopt(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[structopt(long)]
    pub release: bool,
    /// The command used to wrap your application
    #[structopt(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// Arguments to pass to your application
    #[structopt(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Build the project
fn build(opts: &Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build and run the project
pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building eBPF program")?;
    build(&opts).context("Error while building userspace application")?;

    // profile we are building (release or debug)
    let profile = if opts.release { "release" } else { "debug" };
    let bin_path = format!("target/{}/cpu-profiler", profile);

    // arguments to pass to the application
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.as_str());
    args.append(&mut run_args);

    // spawn the command
    let err = Command::new(args.get(0).expect("No first argument"))
        .args(args.iter().skip(1))
        .exec();

    // we shouldn't get here unless the command failed to spawn
    Err(anyhow::Error::from(err).context(format!("Failed to run `{}`", args.join(" "))))
}
