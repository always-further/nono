use crate::cli::LearnArgs;
use crate::{learn, profile};
use colored::Colorize;
use nono::{NonoError, Result};

pub(crate) fn run_learn(args: LearnArgs, silent: bool) -> Result<()> {
    if !silent {
        eprintln!(
            "{}",
            "WARNING: nono learn runs the command WITHOUT any sandbox restrictions.".yellow()
        );
        eprintln!(
            "{}",
            "The command will have full access to your system to discover required paths.".yellow()
        );
        #[cfg(target_os = "macos")]
        eprintln!(
            "{}",
            "NOTE: macOS learn mode uses fs_usage which requires sudo.".yellow()
        );
        eprintln!();
        eprint!("Continue? [y/N] ");

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;

        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            eprintln!("Aborted.");
            return Ok(());
        }
        eprintln!();
    }

    eprintln!("nono learn - Tracing file accesses and network activity...\n");

    let result = learn::run_learn(&args)?;

    if args.json {
        println!("{}", result.to_json()?);
    } else {
        println!("{}", result.to_summary());
    }

    if (result.has_paths() || result.has_network_activity()) && !silent && !args.json {
        offer_save_profile(&result, &args.command)?;
    } else if result.has_paths() || result.has_network_activity() {
        if result.has_paths() {
            eprintln!(
                "\nTo use these paths, add them to your profile or use --read/--write/--allow and --read-file/--write-file/--allow-file flags."
            );
        }
        if result.has_network_activity() {
            eprintln!("Network activity detected. Use --block-net to restrict network access.");
        }
    }

    Ok(())
}

fn offer_save_profile(result: &learn::LearnResult, command: &[String]) -> Result<()> {
    let cmd_name = command
        .first()
        .and_then(|command| std::path::Path::new(command).file_name())
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            NonoError::LearnError("Cannot derive profile name from command".to_string())
        })?;

    eprintln!();
    eprint!("Save as profile? Enter a name (or press Enter to skip): ");

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;

    let input = input.trim();

    if input.is_empty() {
        return Ok(());
    }

    let profile_name = input;

    if !profile_name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
    {
        eprintln!(
            "{}",
            "Invalid profile name. Use only letters, numbers, hyphens, and underscores.".red()
        );
        return Ok(());
    }

    let profile_json = result.to_profile(profile_name, cmd_name)?;

    let config_dir = profile::resolve_user_config_dir()?;
    let profiles_dir = config_dir.join("nono").join("profiles");
    std::fs::create_dir_all(&profiles_dir).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to create profiles directory {}: {}",
            profiles_dir.display(),
            e
        ))
    })?;

    let profile_path = profiles_dir.join(format!("{}.json", profile_name));

    if profile_path.exists() {
        eprint!(
            "Profile '{}' already exists. Overwrite? [y/N] ",
            profile_name
        );
        let mut confirm = String::new();
        std::io::stdin()
            .read_line(&mut confirm)
            .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;
        if !confirm.trim().eq_ignore_ascii_case("y") {
            eprintln!("Skipped.");
            return Ok(());
        }
    }

    std::fs::write(&profile_path, profile_json).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to write profile to {}: {}",
            profile_path.display(),
            e
        ))
    })?;

    eprintln!("\n{} {}", "Profile saved:".green(), profile_path.display());
    eprintln!(
        "Run with: {} {} -- {}",
        "nono run --profile".bold(),
        profile_name,
        command.join(" ")
    );

    Ok(())
}
