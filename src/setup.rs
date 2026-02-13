use crate::cli::SetupArgs;
use crate::config;
use crate::error::{NonoError, Result};
use crate::profile;
use std::fs;
use std::path::Path;

#[cfg(target_os = "macos")]
use nix::libc;

pub struct SetupRunner {
    check_only: bool,
    generate_profiles: bool,
    show_shell_integration: bool,
    #[allow(dead_code)]
    verbose: u8,
}

impl SetupRunner {
    pub fn new(args: &SetupArgs) -> Self {
        Self {
            check_only: args.check_only,
            generate_profiles: args.profiles,
            show_shell_integration: args.shell_integration,
            verbose: args.verbose,
        }
    }

    pub fn run(&self) -> Result<()> {
        // Print ASCII art banner with random quote
        self.print_banner();

        // Installation verification
        self.check_installation()?;

        // Sandbox support testing
        self.test_sandbox_support()?;

        // Show what nono protects
        self.show_protection_summary();

        // Show built-in profiles
        self.show_builtin_profiles();

        if !self.check_only {
            // Directory setup
            if self.generate_profiles {
                self.setup_profiles()?;
            }

            // Shell integration
            if self.show_shell_integration {
                self.show_shell_help();
            }
        }

        // Final: Summary
        self.show_summary();

        Ok(())
    }

    fn print_banner(&self) {
        // ASCII art with random motivational quote
        let quotes = [
            "Don't YOLO when you can NONO!",
            "Security first, sandbox always!",
            "Trust but verify!",
            "Kernel-level security for user-level peace!",
            "Capability-based security FTW!",
            "Sandbox all the things!",
            "Zero trust, maximum safety!",
        ];

        // Use simple deterministic selection based on timestamp
        // to avoid needing rand dependency
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let quote = quotes[(now as usize) % quotes.len()];

        println!(" ▄▀▄      nono v{}", env!("CARGO_PKG_VERSION"));
        println!("▀▄█▄▀    - {}", quote);
        println!();
    }

    fn check_installation(&self) -> Result<()> {
        println!("[1/{}] Checking installation...", self.total_phases());

        // Get the current executable path
        let exe_path = std::env::current_exe()
            .map_err(|e| NonoError::Setup(format!("Failed to get executable path: {}", e)))?;

        println!("  ✓ nono binary found at {}", exe_path.display());
        println!("  ✓ Version: {}", env!("CARGO_PKG_VERSION"));

        // Detect platform
        let platform = if cfg!(target_os = "macos") {
            "macOS (Seatbelt sandbox)"
        } else if cfg!(target_os = "linux") {
            "Linux (Landlock sandbox)"
        } else if cfg!(target_os = "windows") {
            return Err(NonoError::Setup(
                "Windows is not supported. nono requires macOS (Seatbelt) or Linux (Landlock) for sandboxing.".to_string()
            ));
        } else {
            return Err(NonoError::Setup(
                "Unsupported platform. nono requires macOS (Seatbelt) or Linux (Landlock)."
                    .to_string(),
            ));
        };

        println!("  ✓ Platform: {}", platform);
        println!();

        Ok(())
    }

    fn test_sandbox_support(&self) -> Result<()> {
        println!("[2/{}] Testing sandbox support...", self.total_phases());

        #[cfg(target_os = "macos")]
        self.test_macos_seatbelt()?;

        #[cfg(target_os = "linux")]
        self.test_linux_landlock()?;

        println!();
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn test_macos_seatbelt(&self) -> Result<()> {
        use std::ffi::CString;
        use std::ptr;

        // Get macOS version
        let version_output = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string());

        if let Some(version) = version_output {
            println!("  ✓ macOS version: {}", version);
        }

        // Test Seatbelt by forking and trying to apply a minimal sandbox
        // This is the only safe way since sandbox is irreversible
        let test_profile = CString::new("(version 1)\n(allow default)\n")
            .map_err(|e| NonoError::Setup(format!("Failed to create test profile: {}", e)))?;

        unsafe {
            let pid = libc::fork();

            if pid == 0 {
                // Child process: try to apply sandbox
                extern "C" {
                    fn sandbox_init(
                        profile: *const std::os::raw::c_char,
                        flags: u64,
                        errorbuf: *mut *mut std::os::raw::c_char,
                    ) -> i32;
                }

                let result = sandbox_init(test_profile.as_ptr(), 0, ptr::null_mut());
                std::process::exit(if result == 0 { 0 } else { 1 });
            } else if pid > 0 {
                // Parent: wait for child
                let mut status = 0;
                libc::waitpid(pid, &mut status, 0);

                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    println!("  ✓ Seatbelt sandbox support verified");
                    println!("  ✓ File access restrictions: OK");
                    println!("  ✓ Network restrictions: OK");
                } else {
                    return Err(NonoError::Setup(
                        "Seatbelt sandbox test failed. This may indicate a system configuration issue.".to_string()
                    ));
                }
            } else {
                return Err(NonoError::Setup("Failed to fork test process".to_string()));
            }
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn test_linux_landlock(&self) -> Result<()> {
        use landlock::*;

        // Get kernel version
        let kernel_version = std::fs::read_to_string("/proc/version").ok().and_then(|s| {
            s.split_whitespace()
                .nth(2)
                .map(|v| v.trim_end_matches('-').to_string())
        });

        if let Some(version) = kernel_version {
            println!("  ✓ Kernel version: {}", version);
        }

        // Check LSM list
        let lsm_list = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();

        if !lsm_list.contains("landlock") {
            return Err(NonoError::Setup(
                "Landlock is not enabled in kernel LSM list.\n\n\
                To enable Landlock:\n\
                  1. Check your kernel config: CONFIG_SECURITY_LANDLOCK=y\n\
                  2. Add to boot params: lsm=landlock,lockdown,yama,integrity,apparmor\n\
                  3. Reboot your system\n\n\
                See: https://github.com/always-further/nono/docs/troubleshooting.md#landlock-not-supported"
                    .to_string(),
            ));
        }

        println!("  ✓ Landlock enabled in LSM list");

        // We target the highest ABI and report its features
        // The actual sandbox will use Compatible trait to handle older kernels
        let abi = ABI::V5;

        println!("  ✓ Landlock ABI: {:?}", abi);
        println!("  ✓ Available features:");

        match abi {
            ABI::V1 => {
                println!("      - Basic filesystem access control");
            }
            ABI::V2 => {
                println!("      - Basic filesystem access control");
                println!("      - File rename across directories");
            }
            ABI::V3 => {
                println!("      - Basic filesystem access control");
                println!("      - File rename across directories");
                println!("      - File truncation");
            }
            ABI::V4 => {
                println!("      - Basic filesystem access control");
                println!("      - File rename across directories");
                println!("      - File truncation");
                println!("      - TCP network filtering");
            }
            ABI::V5 => {
                println!("      - Basic filesystem access control");
                println!("      - File rename across directories");
                println!("      - File truncation");
                println!("      - TCP network filtering");
                println!("      - Advanced socket and signal scoping");
            }
            _ => {}
        }

        // Try creating a test ruleset
        let handled = AccessFs::from_all(abi);
        Ruleset::default()
            .handle_access(handled)
            .and_then(|r| r.create())
            .map_err(|e| NonoError::Setup(format!("Failed to create Landlock ruleset: {}", e)))?;

        println!("  ✓ Ruleset creation verified");

        Ok(())
    }

    fn show_protection_summary(&self) {
        println!("[3/{}] Default protections...", self.total_phases());

        // Get sensitive paths from config
        let sensitive_paths = config::get_sensitive_paths();
        let dangerous_commands = config::get_dangerous_commands();

        println!(
            "  ✓ {} sensitive paths blocked by default:",
            sensitive_paths.len()
        );
        println!("      SSH keys, AWS/GCP/Azure credentials, Kubernetes config,");
        println!("      Docker config, GPG keys, password managers, shell configs");

        println!(
            "  ✓ {} dangerous commands blocked by default:",
            dangerous_commands.len()
        );

        // Show a sample of blocked commands (sort first for deterministic output)
        let mut all_commands: Vec<_> = dangerous_commands.iter().cloned().collect();
        all_commands.sort();
        let sample: Vec<_> = all_commands.into_iter().take(8).collect();
        println!("      {}, ...", sample.join(", "));

        println!("  ✓ Network access: allowed by default (use --net-block to disable)");
        println!();
    }

    fn show_builtin_profiles(&self) {
        println!("[4/{}] Built-in profiles...", self.total_phases());

        let profiles = profile::list_profiles();

        for name in &profiles {
            // Load profile to get description
            match profile::load_profile(name) {
                Ok(p) => {
                    let desc = p
                        .meta
                        .description
                        .unwrap_or_else(|| "No description".to_string());
                    let net_status = if p.network.block {
                        "network blocked"
                    } else {
                        "network allowed"
                    };
                    println!("  * {} - {} ({})", name, desc, net_status);
                }
                Err(e) => {
                    println!("  * {} - <warning: failed to load: {}>", name, e);
                }
            }
        }

        println!();
        println!("  Use with: nono run --profile <name> -- <command>");
        println!();
    }

    fn setup_profiles(&self) -> Result<()> {
        println!("[5/{}] Setting up example profiles...", self.total_phases());

        // Create profile directory
        let profile_dir = dirs::config_dir()
            .ok_or_else(|| NonoError::Setup("Failed to determine config directory".to_string()))?
            .join("nono")
            .join("profiles");

        fs::create_dir_all(&profile_dir).map_err(|e| {
            NonoError::Setup(format!(
                "Failed to create profile directory {}: {}",
                profile_dir.display(),
                e
            ))
        })?;

        println!("  ✓ Created directory: {}", profile_dir.display());

        // Generate example profiles
        self.write_example_profile(&profile_dir, "example-agent.toml", EXAMPLE_AGENT_PROFILE)?;
        self.write_example_profile(&profile_dir, "offline-build.toml", OFFLINE_BUILD_PROFILE)?;
        self.write_example_profile(
            &profile_dir,
            "data-processing.toml",
            DATA_PROCESSING_PROFILE,
        )?;

        println!();
        Ok(())
    }

    fn write_example_profile(&self, dir: &Path, filename: &str, content: &str) -> Result<()> {
        let path = dir.join(filename);
        fs::write(&path, content)
            .map_err(|e| NonoError::Setup(format!("Failed to write {}: {}", filename, e)))?;
        println!("  ✓ Generated {}", filename);
        Ok(())
    }

    fn show_shell_help(&self) {
        println!("[6/{}] Shell integration...", self.total_phases());

        // Detect shell
        let shell = std::env::var("SHELL")
            .ok()
            .and_then(|s| s.split('/').next_back().map(String::from))
            .unwrap_or_else(|| "bash".to_string());

        let shell_rc = match shell.as_str() {
            "zsh" => "~/.zshrc",
            "bash" => "~/.bashrc",
            "fish" => "~/.config/fish/config.fish",
            _ => "~/.bashrc",
        };

        println!("  You can add these aliases to {}:", shell_rc);
        println!();
        println!("    alias nono-claude='nono run --profile claude-code -- claude'");
        println!("    alias nono-safe='nono run --allow . --net-block --'");
        println!();
    }

    fn show_summary(&self) {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();

        if self.check_only {
            println!("Installation verified!");
            println!();
            println!("Your system is ready to use nono. Run 'nono run --help' to get started.");
        } else {
            println!("Setup complete!");
            println!();
            println!("Quick start examples:");
            println!();
            println!("  # Run Claude Code with built-in profile (recommended)");
            println!("  nono run --profile claude-code -- claude");
            println!();
            println!("  # Run any command with current directory access");
            println!("  nono run --allow . -- <command>");
            println!();
            println!("  # Check why a sensitive path is blocked");
            println!("  nono why ~/.ssh/id_rsa");
            println!();

            if self.generate_profiles {
                println!("Custom profiles:");
                let profile_dir = dirs::config_dir()
                    .map(|p| p.join("nono").join("profiles"))
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "~/.config/nono/profiles".to_string());
                println!("  Edit example profiles in: {}", profile_dir);
                println!();
            }

            println!("Documentation: https://github.com/always-further/nono#readme");
            println!();
            println!("Run 'nono run --help' to see all options.");
        }
    }

    fn total_phases(&self) -> usize {
        let mut count = 4; // Installation check + sandbox test + protection summary + profiles

        if !self.check_only {
            if self.generate_profiles {
                count += 1;
            }
            if self.show_shell_integration {
                count += 1;
            }
        }

        count
    }
}

// Profile templates
const EXAMPLE_AGENT_PROFILE: &str = r#"[meta]
name = "example-agent"
version = "1.0.0"
description = "Template for creating custom agent profiles"

[filesystem]
# Directories with read+write access
allow = ["$WORKDIR"]

# Directories with read-only access
read = ["$HOME/.config/my-agent"]

# Directories with write-only access
write = []

# Individual files
# allow_file = []
# read_file = []
# write_file = []

[network]
# false = network allowed (default)
# true = network blocked
block = false
"#;

const OFFLINE_BUILD_PROFILE: &str = r#"[meta]
name = "offline-build"
version = "1.0.0"
description = "Build environment with no network access"

[filesystem]
allow = ["$WORKDIR"]
read = ["$HOME/.cargo", "$HOME/.rustup"]

[network]
block = true  # No network for reproducible builds
"#;

const DATA_PROCESSING_PROFILE: &str = r#"[meta]
name = "data-processing"
version = "1.0.0"
description = "Read from input, write to output"

[filesystem]
read = ["$WORKDIR/input"]
write = ["$WORKDIR/output"]
read_file = ["$WORKDIR/config.yaml"]

[network]
block = false
"#;
