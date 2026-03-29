use crate::cli::{RunArgs, SandboxArgs, ShellArgs, WrapArgs};
use crate::exec_strategy;
use crate::execution_runtime::execute_sandboxed;
use crate::launch_runtime::{
    load_configured_detach_sequence, prepare_run_launch_plan, resolve_requested_workdir,
    ExecutionFlags, LaunchPlan, SessionLaunchOptions,
};
use crate::output;
use crate::sandbox_prepare::{
    prepare_sandbox, print_allow_launch_services_warning, validate_external_proxy_bypass,
};
use crate::theme;
use nono::{NonoError, Result};
use std::ffi::OsString;

pub(crate) fn run_sandbox(run_args: RunArgs, silent: bool) -> Result<()> {
    let args = run_args.sandbox.clone();
    let command = run_args.command.clone();

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut command_iter = command.into_iter();
    let program = OsString::from(command_iter.next().ok_or(NonoError::NoCommand)?);
    let cmd_args: Vec<OsString> = command_iter.map(OsString::from).collect();

    if args.dry_run {
        let prepared = prepare_sandbox(&args, silent)?;
        validate_external_proxy_bypass(&args, &prepared)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        output::print_dry_run(&program, &cmd_args, silent);
        return Ok(());
    }

    let launch_plan = prepare_run_launch_plan(run_args, program, cmd_args, silent)?;
    execute_sandboxed(launch_plan)
}

pub(crate) fn run_shell(args: ShellArgs, silent: bool) -> Result<()> {
    let shell_path = args
        .shell
        .or_else(|| {
            std::env::var("SHELL")
                .ok()
                .filter(|shell| !shell.is_empty())
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| std::path::PathBuf::from("/bin/sh"));

    if args.sandbox.dry_run {
        let prepared = prepare_sandbox(&args.sandbox, silent)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        output::print_dry_run(shell_path.as_os_str(), &[], silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args.sandbox, silent)?;

    if prepared.allow_launch_services_active {
        print_allow_launch_services_warning(silent);
    }

    if !silent {
        eprintln!("{}", {
            let theme = theme::current();
            theme::fg("Exit the shell with Ctrl-D or 'exit'.", theme.subtext)
        });
        eprintln!();
    }

    execute_sandboxed(LaunchPlan {
        program: shell_path.into_os_string(),
        cmd_args: vec![],
        caps: prepared.caps,
        loaded_secrets: prepared.secrets,
        flags: ExecutionFlags {
            workdir: resolve_requested_workdir(args.sandbox.workdir.as_ref()),
            no_diagnostics: true,
            capability_elevation: prepared.capability_elevation,
            override_deny_paths: prepared.override_deny_paths,
            session: SessionLaunchOptions {
                session_name: args.name,
                detach_sequence: load_configured_detach_sequence()?,
                ..SessionLaunchOptions::default()
            },
            ..ExecutionFlags::defaults(silent)?
        },
    })
}

pub(crate) fn run_wrap(wrap_args: WrapArgs, silent: bool) -> Result<()> {
    let args: SandboxArgs = wrap_args.sandbox.into();
    let command = wrap_args.command;
    let no_diagnostics = wrap_args.no_diagnostics;

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut command_iter = command.into_iter();
    let program = OsString::from(command_iter.next().ok_or(NonoError::NoCommand)?);
    let cmd_args: Vec<OsString> = command_iter.map(OsString::from).collect();

    if args.dry_run {
        let prepared = prepare_sandbox(&args, silent)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        output::print_dry_run(&program, &cmd_args, silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args, silent)?;

    if prepared.upstream_proxy.is_some()
        || matches!(
            prepared.caps.network_mode(),
            nono::NetworkMode::ProxyOnly { .. }
        )
    {
        return Err(NonoError::ConfigParse(
            "nono wrap does not support proxy mode (activated by profile network settings). \
             Use `nono run` instead."
                .to_string(),
        ));
    }

    if prepared.allow_launch_services_active {
        print_allow_launch_services_warning(silent);
    }

    execute_sandboxed(LaunchPlan {
        program,
        cmd_args,
        caps: prepared.caps,
        loaded_secrets: prepared.secrets,
        flags: ExecutionFlags {
            strategy: exec_strategy::ExecStrategy::Direct,
            workdir: resolve_requested_workdir(args.workdir.as_ref()),
            no_diagnostics,
            override_deny_paths: prepared.override_deny_paths,
            ..ExecutionFlags::defaults(silent)?
        },
    })
}
