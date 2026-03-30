//! Integration tests for environment variables and Windows smoke execution.
//!
//! These run as separate processes, so env vars are isolated and cannot race
//! with parallel unit tests.

use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

/// Combine stdout + stderr for assertion checking (nono writes UX to stderr).
fn combined_output(output: &std::process::Output) -> String {
    let mut s = String::from_utf8_lossy(&output.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&output.stderr));
    s
}

#[cfg(target_os = "windows")]
fn expected_windows_runtime_root(seed_dir: &std::path::Path) -> std::path::PathBuf {
    let low_root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .map(|local| local.join("Temp").join("Low"));
    let local_low_root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .and_then(|local| local.parent().map(|root| root.join("LocalLow")));
    if low_root
        .as_ref()
        .is_some_and(|prefix| seed_dir.starts_with(prefix))
        || local_low_root
            .as_ref()
            .is_some_and(|prefix| seed_dir.starts_with(prefix))
    {
        seed_dir.join(".nono-runtime")
    } else {
        low_root
            .unwrap_or_else(|| seed_dir.join(".nono-runtime-low"))
            .join("nono")
            .join(seed_dir.to_string_lossy().replace(['\\', '/', ':'], "_"))
    }
}

#[test]
fn env_nono_allow_comma_separated() {
    let output = nono_bin()
        .env("NONO_ALLOW", "/tmp/a,/tmp/b")
        .args(["run", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        text.contains("/tmp/a") && text.contains("/tmp/b"),
        "expected both paths in dry-run output, got:\n{text}"
    );
}

#[test]
fn env_nono_block_net() {
    let output = nono_bin()
        .env("NONO_BLOCK_NET", "1")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        text.contains("blocked"),
        "expected network blocked in dry-run output, got:\n{text}"
    );
}

#[test]
fn env_nono_block_net_accepts_true() {
    let output = nono_bin()
        .env("NONO_BLOCK_NET", "true")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_BLOCK_NET=true should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn legacy_env_nono_net_block_still_works() {
    let output = nono_bin()
        .env("NONO_NET_BLOCK", "1")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        text.contains("blocked"),
        "expected legacy NONO_NET_BLOCK to still block network, got:\n{text}"
    );
}

#[test]
fn env_nono_profile() {
    let output = nono_bin()
        .env("NONO_PROFILE", "claude-code")
        .args(["run", "--dry-run", "--allow-cwd", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_PROFILE=claude-code should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_network_profile() {
    let output = nono_bin()
        .env("NONO_NETWORK_PROFILE", "claude-code")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_NETWORK_PROFILE should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_flag_overrides_env_var() {
    // CLI --profile should override NONO_PROFILE env var.
    // "nonexistent-profile-from-env" would fail if used, but CLI wins.
    let output = nono_bin()
        .env("NONO_PROFILE", "nonexistent-profile-from-env")
        .args([
            "run",
            "--profile",
            "claude-code",
            "--dry-run",
            "--allow-cwd",
            "echo",
        ])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "CLI --profile should override env var, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_upstream_proxy() {
    let output = nono_bin()
        .env("NONO_UPSTREAM_PROXY", "squid.corp:3128")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_UPSTREAM_PROXY should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_upstream_bypass_comma_separated() {
    let output = nono_bin()
        .env("NONO_UPSTREAM_PROXY", "squid.corp:3128")
        .env("NONO_UPSTREAM_BYPASS", "internal.corp,*.private.net")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "NONO_UPSTREAM_BYPASS should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_nono_upstream_bypass_requires_upstream_proxy() {
    // NONO_UPSTREAM_BYPASS without NONO_UPSTREAM_PROXY should fail
    let output = nono_bin()
        .env("NONO_UPSTREAM_BYPASS", "internal.corp")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "NONO_UPSTREAM_BYPASS without NONO_UPSTREAM_PROXY should fail"
    );
}

#[test]
fn env_allow_net_conflicts_with_upstream_proxy() {
    // NONO_ALLOW_NET + NONO_UPSTREAM_PROXY should conflict at the clap level.
    let output = nono_bin()
        .env("NONO_UPSTREAM_PROXY", "squid.corp:3128")
        .env("NONO_ALLOW_NET", "true")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "NONO_ALLOW_NET + NONO_UPSTREAM_PROXY should conflict"
    );
}

#[test]
fn allow_net_overrides_profile_external_proxy() {
    // A profile with external_proxy should be overridden by --allow-net,
    // resulting in unrestricted network (no proxy mode activation).
    let dir = tempfile::tempdir().expect("tmpdir");
    let profile_path = dir.path().join("ext-proxy-profile.json");
    std::fs::write(
        &profile_path,
        r#"{
            "meta": { "name": "ext-proxy-test" },
            "network": { "external_proxy": "squid.corp:3128" }
        }"#,
    )
    .expect("write profile");

    let output = nono_bin()
        .args([
            "run",
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--allow-net",
            "--allow",
            "/tmp",
            "--dry-run",
            "echo",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "--allow-net should override profile external_proxy, stderr: {text}"
    );
    // Should show "allowed" network, not proxy mode
    assert!(
        text.contains("allowed"),
        "expected unrestricted network in dry-run output, got:\n{text}"
    );
}

#[test]
fn env_conflict_allow_net_and_block_net() {
    let output = nono_bin()
        .env("NONO_ALLOW_NET", "true")
        .env("NONO_BLOCK_NET", "true")
        .args(["run", "--allow", "/tmp", "--dry-run", "echo"])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "NONO_ALLOW_NET + NONO_BLOCK_NET should conflict"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_dry_run_reports_preview_validation_without_enforcement_claims() {
    let output = nono_bin()
        .args([
            "run",
            "--dry-run",
            "--profile",
            "codex",
            "--",
            "cmd",
            "/c",
            "echo",
            "test",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows dry-run should succeed, output:\n{text}"
    );
    assert!(
        text.contains("Capabilities:"),
        "expected capability summary in dry-run output, got:\n{text}"
    );
    assert!(
        text.contains("$ cmd /c echo test"),
        "expected command preview in dry-run output, got:\n{text}"
    );
    assert!(
        text.contains("preview validation only"),
        "expected preview-validation wording in dry-run output, got:\n{text}"
    );
    assert!(
        !text.contains("sandbox would be applied"),
        "dry-run must not imply enforcement on Windows preview, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_executes_basic_command() {
    let output = nono_bin()
        .args(["run", "--", "cmd", "/c", "echo", "hello"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows direct execution should succeed, output:\n{text}"
    );
    assert!(
        text.contains("hello"),
        "expected child stdout from cmd /c echo hello, got:\n{text}"
    );
    assert!(
        text.contains("basic Windows process containment"),
        "expected preview warning in output, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_rejects_file_grants_in_preview_live_run() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let allowed_file = dir.path().join("allowed.txt");
    std::fs::write(&allowed_file, "hello").expect("write allowed file");
    let allowed_file = allowed_file.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--read-file",
            &allowed_file,
            "--",
            "cmd",
            "/c",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "unsupported Windows file grants should fail closed, output:\n{text}"
    );
    assert!(
        text.contains("preview cannot enforce the requested sandbox controls"),
        "expected intentional Windows preview rejection, got:\n{text}"
    );
    assert!(
        text.contains("filesystem restrictions"),
        "expected filesystem restriction detail in output, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_supported_directory_allowlist_in_preview_live_run() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--read",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "cd",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "supported Windows directory allowlist should succeed, output:\n{text}"
    );
    assert!(
        text.to_ascii_lowercase()
            .contains(&workdir.to_ascii_lowercase()),
        "expected child cwd in output, got:\n{text}"
    );
    assert!(
        text.contains("supported directory allowlists"),
        "expected updated Windows preview warning, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_read_only_allowlist_still_reads_inside_policy() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let file = workspace.join("inside.txt");
    std::fs::write(&file, "hello from read-only run").expect("write file");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--read",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "type",
            "inside.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "read-only Windows preview should allow reads, output:\n{text}"
    );
    assert!(
        text.contains("hello from read-only run"),
        "expected child read output, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_read_only_allowlist_blocks_runtime_write_attempt() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let userprofile = std::env::var("USERPROFILE").expect("USERPROFILE");
    let probe_path = std::path::Path::new(&userprofile).join(format!(
        "nono-low-integrity-write-probe-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&probe_path);
    let command = format!("echo denied> \"{}\"", probe_path.display());

    let output = nono_bin()
        .args([
            "run",
            "--read",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            &command,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "read-only Windows preview should block runtime writes, output:\n{text}"
    );
    assert!(
        !probe_path.exists(),
        "probe file should not be created under read-only low-integrity launch"
    );
    let _ = std::fs::remove_file(&probe_path);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_redirects_temp_vars_into_writable_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo TMP=%TMP% TEMP=%TEMP% TMPDIR=%TMPDIR%",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview temp redirection should succeed, output:\n{text}"
    );
    let normalized = text.to_ascii_lowercase();
    let runtime_root = expected_windows_runtime_root(&workspace);
    let tmp_root_lower = runtime_root
        .join("tmp")
        .to_string_lossy()
        .to_ascii_lowercase();
    assert!(
        normalized.contains(&format!("tmp={}\\", tmp_root_lower))
            || normalized.contains(&format!("tmp={}/", tmp_root_lower))
            || normalized.contains(&format!("tmp={}", tmp_root_lower)),
        "expected TMP inside writable allowlist, got:\n{text}"
    );
    assert!(
        normalized.contains(&format!("temp={}\\", tmp_root_lower))
            || normalized.contains(&format!("temp={}/", tmp_root_lower))
            || normalized.contains(&format!("temp={}", tmp_root_lower)),
        "expected TEMP inside writable allowlist, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_redirects_profile_state_vars_into_writable_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo PATH=%PATH% PATHEXT=%PATHEXT% COMSPEC=%COMSPEC% SystemRoot=%SystemRoot% windir=%windir% SystemDrive=%SystemDrive% NoDefaultCurrentDirectoryInExePath=%NoDefaultCurrentDirectoryInExePath% APPDATA=%APPDATA% LOCALAPPDATA=%LOCALAPPDATA% HOME=%HOME% USERPROFILE=%USERPROFILE% XDG_CONFIG_HOME=%XDG_CONFIG_HOME% XDG_DATA_HOME=%XDG_DATA_HOME% PROGRAMDATA=%PROGRAMDATA% ALLUSERSPROFILE=%ALLUSERSPROFILE% PUBLIC=%PUBLIC% ProgramFiles=%ProgramFiles% ProgramFiles(x86)=%ProgramFiles(x86)% ProgramW6432=%ProgramW6432% CommonProgramFiles=%CommonProgramFiles% CommonProgramFiles(x86)=%CommonProgramFiles(x86)% CommonProgramW6432=%CommonProgramW6432% OneDrive=%OneDrive% INETCACHE=%INETCACHE% INETCOOKIES=%INETCOOKIES% INETHISTORY=%INETHISTORY% PSModulePath=%PSModulePath% PSModuleAnalysisCachePath=%PSModuleAnalysisCachePath% CARGO_HOME=%CARGO_HOME% RUSTUP_HOME=%RUSTUP_HOME% DOTNET_CLI_HOME=%DOTNET_CLI_HOME% NUGET_PACKAGES=%NUGET_PACKAGES% NUGET_HTTP_CACHE_PATH=%NUGET_HTTP_CACHE_PATH% NUGET_PLUGINS_CACHE_PATH=%NUGET_PLUGINS_CACHE_PATH% ChocolateyInstall=%ChocolateyInstall% ChocolateyToolsLocation=%ChocolateyToolsLocation% VCPKG_ROOT=%VCPKG_ROOT% NPM_CONFIG_CACHE=%NPM_CONFIG_CACHE% YARN_CACHE_FOLDER=%YARN_CACHE_FOLDER% PIP_CACHE_DIR=%PIP_CACHE_DIR% PIP_BUILD_TRACKER=%PIP_BUILD_TRACKER% PYTHONPYCACHEPREFIX=%PYTHONPYCACHEPREFIX% PYTHONUSERBASE=%PYTHONUSERBASE% GOCACHE=%GOCACHE% GOMODCACHE=%GOMODCACHE% GOPATH=%GOPATH% HISTFILE=%HISTFILE% LESSHISTFILE=%LESSHISTFILE% NODE_REPL_HISTORY=%NODE_REPL_HISTORY% PYTHONHISTFILE=%PYTHONHISTFILE% SQLITE_HISTORY=%SQLITE_HISTORY% IPYTHONDIR=%IPYTHONDIR% GEM_HOME=%GEM_HOME% GEM_PATH=%GEM_PATH% BUNDLE_USER_HOME=%BUNDLE_USER_HOME% BUNDLE_USER_CACHE=%BUNDLE_USER_CACHE% BUNDLE_USER_CONFIG=%BUNDLE_USER_CONFIG% COMPOSER_HOME=%COMPOSER_HOME% COMPOSER_CACHE_DIR=%COMPOSER_CACHE_DIR% GRADLE_USER_HOME=%GRADLE_USER_HOME% MAVEN_USER_HOME=%MAVEN_USER_HOME%",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview profile-state redirection should succeed, output:\n{text}"
    );
    let normalized = text.to_ascii_lowercase();
    let runtime_root = expected_windows_runtime_root(&workspace);
    let runtime_root_lower = runtime_root.to_string_lossy().to_ascii_lowercase();
    assert!(
        normalized.contains("path=c:\\windows\\system32;")
            || normalized.contains("path=c:\\windows\\system32\\"),
        "expected PATH to start from the Windows runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("pathext=.com;.exe;.bat;.cmd"),
        "expected PATHEXT runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("comspec=c:\\windows\\system32\\cmd.exe"),
        "expected COMSPEC runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("systemroot=c:\\windows"),
        "expected SystemRoot runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("windir=c:\\windows"),
        "expected windir runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("systemdrive=c:"),
        "expected SystemDrive runtime baseline, got:\n{text}"
    );
    assert!(
        normalized.contains("nodefaultcurrentdirectoryinexepath=1"),
        "expected NoDefaultCurrentDirectoryInExePath runtime baseline, got:\n{text}"
    );
    for key in [
        "appdata=",
        "localappdata=",
        "home=",
        "userprofile=",
        "xdg_config_home=",
        "xdg_data_home=",
        "programdata=",
        "allusersprofile=",
        "public=",
        "programfiles=",
        "programfiles(x86)=",
        "programw6432=",
        "commonprogramfiles=",
        "commonprogramfiles(x86)=",
        "commonprogramw6432=",
        "onedrive=",
        "inetcache=",
        "inetcookies=",
        "inethistory=",
        "psmodulepath=",
        "psmoduleanalysiscachepath=",
        "cargo_home=",
        "rustup_home=",
        "dotnet_cli_home=",
        "nuget_packages=",
        "nuget_http_cache_path=",
        "nuget_plugins_cache_path=",
        "chocolateyinstall=",
        "chocolateytoolslocation=",
        "vcpkg_root=",
        "npm_config_cache=",
        "yarn_cache_folder=",
        "pip_cache_dir=",
        "pip_build_tracker=",
        "pythonpycacheprefix=",
        "pythonuserbase=",
        "gocache=",
        "gomodcache=",
        "gopath=",
        "histfile=",
        "lesshistfile=",
        "node_repl_history=",
        "pythonhistfile=",
        "sqlite_history=",
        "ipythondir=",
        "gem_home=",
        "gem_path=",
        "bundle_user_home=",
        "bundle_user_cache=",
        "bundle_user_config=",
        "composer_home=",
        "composer_cache_dir=",
        "gradle_user_home=",
        "maven_user_home=",
    ] {
        assert!(
            normalized.contains(&format!("{key}{runtime_root_lower}\\"))
                || normalized.contains(&format!("{key}{runtime_root_lower}/"))
                || normalized.contains(&format!("{key}{runtime_root_lower}")),
            "expected {key} inside writable allowlist, got:\n{text}"
        );
    }
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_filters_host_toolchain_home_vars_without_runtime_dir() {
    let output = nono_bin()
        .env("CARGO_HOME", r"C:\host-cargo")
        .env("RUSTUP_HOME", r"C:\host-rustup")
        .env("NUGET_PACKAGES", r"C:\host-nuget")
        .env("DOTNET_CLI_HOME", r"C:\host-dotnet")
        .env("PSModuleAnalysisCachePath", r"C:\host-psmodule-analysis\cache")
        .env("ChocolateyInstall", r"C:\ProgramData\chocolatey")
        .env("VCPKG_ROOT", r"C:\vcpkg")
        .env("NUGET_HTTP_CACHE_PATH", r"C:\host-nuget-http")
        .env("NUGET_PLUGINS_CACHE_PATH", r"C:\host-nuget-plugins")
        .env("NPM_CONFIG_CACHE", r"C:\host-npm")
        .env("YARN_CACHE_FOLDER", r"C:\host-yarn")
        .env("PIP_CACHE_DIR", r"C:\host-pip")
        .env("PIP_BUILD_TRACKER", r"C:\host-pip-build-tracker")
        .env("PYTHONPYCACHEPREFIX", r"C:\host-python-pycache")
        .env("PYTHONUSERBASE", r"C:\host-python-userbase")
        .env("GOCACHE", r"C:\host-go-cache")
        .env("GOMODCACHE", r"C:\host-go-mod-cache")
        .env("GOPATH", r"C:\host-go-path")
        .env("HISTFILE", r"C:\host-history\shell")
        .env("LESSHISTFILE", r"C:\host-history\less")
        .env("NODE_REPL_HISTORY", r"C:\host-history\node")
        .env("PYTHONHISTFILE", r"C:\host-history\python")
        .env("SQLITE_HISTORY", r"C:\host-history\sqlite")
        .env("IPYTHONDIR", r"C:\host-history\ipython")
        .env("GEM_HOME", r"C:\host-ruby\gem-home")
        .env("GEM_PATH", r"C:\host-ruby\gem-path")
        .env("BUNDLE_USER_HOME", r"C:\host-bundler\home")
        .env("BUNDLE_USER_CACHE", r"C:\host-bundler\cache")
        .env("BUNDLE_USER_CONFIG", r"C:\host-bundler\config")
        .env("COMPOSER_HOME", r"C:\host-composer\home")
        .env("COMPOSER_CACHE_DIR", r"C:\host-composer\cache")
        .env("GRADLE_USER_HOME", r"C:\host-gradle")
        .env("MAVEN_USER_HOME", r"C:\host-maven")
        .args([
            "run",
            "--",
            "cmd",
            "/c",
            "echo CARGO_HOME=%CARGO_HOME% RUSTUP_HOME=%RUSTUP_HOME% NUGET_PACKAGES=%NUGET_PACKAGES% DOTNET_CLI_HOME=%DOTNET_CLI_HOME% PSModuleAnalysisCachePath=%PSModuleAnalysisCachePath% NUGET_HTTP_CACHE_PATH=%NUGET_HTTP_CACHE_PATH% NUGET_PLUGINS_CACHE_PATH=%NUGET_PLUGINS_CACHE_PATH% ChocolateyInstall=%ChocolateyInstall% VCPKG_ROOT=%VCPKG_ROOT% NPM_CONFIG_CACHE=%NPM_CONFIG_CACHE% YARN_CACHE_FOLDER=%YARN_CACHE_FOLDER% PIP_CACHE_DIR=%PIP_CACHE_DIR% PIP_BUILD_TRACKER=%PIP_BUILD_TRACKER% PYTHONPYCACHEPREFIX=%PYTHONPYCACHEPREFIX% PYTHONUSERBASE=%PYTHONUSERBASE% GOCACHE=%GOCACHE% GOMODCACHE=%GOMODCACHE% GOPATH=%GOPATH% HISTFILE=%HISTFILE% LESSHISTFILE=%LESSHISTFILE% NODE_REPL_HISTORY=%NODE_REPL_HISTORY% PYTHONHISTFILE=%PYTHONHISTFILE% SQLITE_HISTORY=%SQLITE_HISTORY% IPYTHONDIR=%IPYTHONDIR% GEM_HOME=%GEM_HOME% GEM_PATH=%GEM_PATH% BUNDLE_USER_HOME=%BUNDLE_USER_HOME% BUNDLE_USER_CACHE=%BUNDLE_USER_CACHE% BUNDLE_USER_CONFIG=%BUNDLE_USER_CONFIG% COMPOSER_HOME=%COMPOSER_HOME% COMPOSER_CACHE_DIR=%COMPOSER_CACHE_DIR% GRADLE_USER_HOME=%GRADLE_USER_HOME% MAVEN_USER_HOME=%MAVEN_USER_HOME%",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should filter host toolchain-home vars, output:\n{text}"
    );
    let normalized = text.to_ascii_lowercase();
    for key in [
        "cargo_home=",
        "rustup_home=",
        "nuget_packages=",
        "dotnet_cli_home=",
        "psmoduleanalysiscachepath=",
        "nuget_http_cache_path=",
        "nuget_plugins_cache_path=",
        "chocolateyinstall=",
        "vcpkg_root=",
        "npm_config_cache=",
        "yarn_cache_folder=",
        "pip_cache_dir=",
        "pip_build_tracker=",
        "pythonpycacheprefix=",
        "pythonuserbase=",
        "gocache=",
        "gomodcache=",
        "gopath=",
        "histfile=",
        "lesshistfile=",
        "node_repl_history=",
        "pythonhistfile=",
        "sqlite_history=",
        "ipythondir=",
        "gem_home=",
        "gem_path=",
        "bundle_user_home=",
        "bundle_user_cache=",
        "bundle_user_config=",
        "composer_home=",
        "composer_cache_dir=",
        "gradle_user_home=",
        "maven_user_home=",
    ] {
        assert!(
            normalized.contains(key),
            "expected {key} marker in child output, got:\n{text}"
        );
    }
    for leaked in [
        r"c:\host-cargo",
        r"c:\host-rustup",
        r"c:\host-nuget",
        r"c:\host-dotnet",
        r"c:\host-psmodule-analysis\cache",
        r"c:\host-nuget-http",
        r"c:\host-nuget-plugins",
        r"c:\programdata\chocolatey",
        r"c:\vcpkg",
        r"c:\host-npm",
        r"c:\host-yarn",
        r"c:\host-pip",
        r"c:\host-pip-build-tracker",
        r"c:\host-python-pycache",
        r"c:\host-python-userbase",
        r"c:\host-go-cache",
        r"c:\host-go-mod-cache",
        r"c:\host-go-path",
        r"c:\host-history\shell",
        r"c:\host-history\less",
        r"c:\host-history\node",
        r"c:\host-history\python",
        r"c:\host-history\sqlite",
        r"c:\host-history\ipython",
        r"c:\host-ruby\gem-home",
        r"c:\host-ruby\gem-path",
        r"c:\host-bundler\home",
        r"c:\host-bundler\cache",
        r"c:\host-bundler\config",
        r"c:\host-composer\home",
        r"c:\host-composer\cache",
        r"c:\host-gradle",
        r"c:\host-maven",
    ] {
        assert!(
            !normalized.contains(leaked),
            "host toolchain path leaked into child env: {leaked}\n{text}"
        );
    }
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_cmd_write_into_redirected_tmp_runtime_dir() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo redirected>%TMP%\\probe.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow runtime-owned tmp writes inside allowlist, output:\n{text}"
    );
    let dest = expected_windows_runtime_root(&workspace)
        .join("tmp")
        .join("probe.txt");
    assert!(dest.exists(), "expected copied file at {}", dest.display());
    assert_eq!(
        std::fs::read_to_string(&dest).expect("read dest").trim(),
        "redirected"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_workspace_write_even_with_writable_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo denied> workspace-write.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block direct workspace writes under low-integrity enforcement, output:\n{text}"
    );
    assert!(
        !workspace.join("workspace-write.txt").exists(),
        "workspace write probe should not be created under low-integrity writable allowlist"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_direct_write_inside_low_integrity_allowlisted_dir() {
    let low_root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .map(|local| local.join("Temp").join("Low"))
        .expect("LOCALAPPDATA should be set on Windows");
    std::fs::create_dir_all(&low_root).expect("ensure low root");

    let unique = format!(
        "nono-low-write-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix epoch")
            .as_nanos()
    );
    let workspace = low_root.join(unique);
    std::fs::create_dir_all(&workspace).expect("mkdir low-integrity workspace");

    let allowed = workspace.to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo direct> direct-write.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow direct writes inside low-integrity allowlisted dirs, output:\n{text}"
    );
    let probe = workspace.join("direct-write.txt");
    assert!(
        probe.exists(),
        "expected direct write at {}",
        probe.display()
    );
    assert_eq!(
        std::fs::read_to_string(&probe)
            .expect("read direct write")
            .trim(),
        "direct"
    );

    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_dir_all(&workspace);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_direct_write_inside_locallow_allowlisted_dir() {
    let local_low_root = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .and_then(|local| local.parent().map(|root| root.join("LocalLow")))
        .expect("LOCALAPPDATA should resolve LocalLow on Windows");
    if let Err(err) = std::fs::create_dir_all(&local_low_root) {
        eprintln!(
            "skipping LocalLow direct-write test because the LocalLow root is unavailable: {err}"
        );
        return;
    }

    let unique = format!(
        "nono-locallow-write-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix epoch")
            .as_nanos()
    );
    let workspace = local_low_root.join(unique);
    if let Err(err) = std::fs::create_dir_all(&workspace) {
        eprintln!(
            "skipping LocalLow direct-write test because the LocalLow workspace could not be created: {err}"
        );
        return;
    }

    let allowed = workspace.to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo direct> direct-write.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow direct writes inside LocalLow allowlisted dirs, output:\n{text}"
    );
    let probe = workspace.join("direct-write.txt");
    assert!(
        probe.exists(),
        "expected direct write at {}",
        probe.display()
    );
    assert_eq!(
        std::fs::read_to_string(&probe)
            .expect("read direct write")
            .trim(),
        "direct"
    );

    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_dir_all(&workspace);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_cmd_type_for_relative_file_inside_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let file = workspace.join("inside.txt");
    std::fs::write(&file, "hello from type").expect("write file");

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "type",
            "inside.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow cmd /c type inside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("hello from type"),
        "expected file contents from cmd /c type, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_cmd_copy_to_absolute_destination_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let source = workspace.join("source.txt");
    std::fs::write(&source, "copied").expect("write source");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_dest = outside_dir.path().join("dest.txt");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside_dest = outside_dest.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "copy",
            "source.txt",
            &outside_dest,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block cmd /c copy outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("destination path argument"),
        "expected destination path rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_powershell_get_content_inside_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let file = workspace.join("inside.txt");
    std::fs::write(&file, "hello from powershell").expect("write file");

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "powershell.exe",
            "-Command",
            "Get-Content inside.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow PowerShell Get-Content inside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("hello from powershell"),
        "expected file contents from PowerShell Get-Content, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_powershell_copy_into_redirected_tmp_runtime_dir() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let source = workspace.join("source.txt");
    std::fs::write(&source, "copied by powershell").expect("write source");

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "powershell.exe",
            "-Command",
            "$dest = Join-Path $env:TEMP 'dest.txt'; Copy-Item source.txt -Destination $dest; Get-Content $dest",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow PowerShell Copy-Item into redirected tmp runtime dir, output:\n{text}"
    );
    let dest = expected_windows_runtime_root(&workspace)
        .join("tmp")
        .join("dest.txt");
    assert!(dest.exists(), "expected copied file at {}", dest.display());
    assert_eq!(
        std::fs::read_to_string(&dest).expect("read dest"),
        "copied by powershell"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_allows_findstr_inside_allowlist() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let file = workspace.join("inside.txt");
    std::fs::write(&file, "needle in a haystack").expect("write file");

    let allowed = dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "findstr.exe",
            "/c:needle",
            "needle",
            "inside.txt",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows preview should allow findstr inside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("needle in a haystack"),
        "expected file contents from findstr, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_xcopy_destination_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let source = workspace.join("source.txt");
    std::fs::write(&source, "copied").expect("write source");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_dest = outside_dir.path().join("dest.txt");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside_dest = outside_dest.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "xcopy.exe",
            "source.txt",
            &outside_dest,
            "/Y",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block xcopy outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("xcopy destination path"),
        "expected xcopy destination rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_comp_file_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let inside = workspace.join("inside.txt");
    std::fs::write(&inside, "same").expect("write inside");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside = outside_dir.path().join("outside.txt");
    std::fs::write(&outside, "same").expect("write outside");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside = outside.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "comp.exe",
            "inside.txt",
            &outside,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block comp outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("comp file argument"),
        "expected comp path rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_fc_file_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let inside = workspace.join("inside.txt");
    std::fs::write(&inside, "same").expect("write inside");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside = outside_dir.path().join("outside.txt");
    std::fs::write(&outside, "same").expect("write outside");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside = outside.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "fc.exe",
            "inside.txt",
            &outside,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block fc outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("fc file argument"),
        "expected fc path rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_cscript_destination_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let script = workspace.join("copy.vbs");
    std::fs::write(
        &script,
        r#"Set fso = CreateObject("Scripting.FileSystemObject")
Set source = fso.OpenTextFile(WScript.Arguments(0), 1)
contents = source.ReadAll
source.Close
Set dest = fso.CreateTextFile(WScript.Arguments(1), True)
dest.Write contents
dest.Close
"#,
    )
    .expect("write script");
    let source = workspace.join("source.txt");
    std::fs::write(&source, "copied").expect("write source");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_dest = outside_dir.path().join("dest.txt");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside_dest = outside_dest.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cscript.exe",
            "copy.vbs",
            "source.txt",
            &outside_dest,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block cscript outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument")
            || text.contains("Windows Script Host path argument"),
        "expected cscript destination rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_powershell_copy_to_absolute_destination_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let source = workspace.join("source.txt");
    std::fs::write(&source, "copied").expect("write source");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_dest = outside_dir.path().join("dest.txt");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let command = format!(
        "Copy-Item source.txt -Destination '{}'",
        outside_dest.to_string_lossy()
    );

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "powershell.exe",
            "-Command",
            &command,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block PowerShell copy outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("PowerShell destination path"),
        "expected PowerShell destination rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_directory_allowlist_when_workdir_is_outside_supported_subset() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workdir_dir = tempfile::tempdir().expect("workdir tmpdir");
    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workdir_dir.path().to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--read",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should fail closed when workdir is outside supported subset, output:\n{text}"
    );
    assert!(
        text.contains("filesystem restrictions"),
        "expected filesystem restriction rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_absolute_path_argument_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_file = outside_dir.path().join("outside.txt");
    std::fs::write(&outside_file, "hello").expect("write file");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside_file = outside_file.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "more.com",
            &outside_file,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block absolute path args outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument"),
        "expected absolute path argument rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_cmd_type_for_absolute_file_outside_allowlist() {
    let allowed_dir = tempfile::tempdir().expect("allowed tmpdir");
    let workspace = allowed_dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("mkdir workspace");
    let outside_dir = tempfile::tempdir().expect("outside tmpdir");
    let outside_file = outside_dir.path().join("outside.txt");
    std::fs::write(&outside_file, "outside").expect("write file");

    let allowed = allowed_dir.path().to_string_lossy().into_owned();
    let workdir = workspace.to_string_lossy().into_owned();
    let outside_file = outside_file.to_string_lossy().into_owned();

    let output = nono_bin()
        .args([
            "run",
            "--allow",
            &allowed,
            "--workdir",
            &workdir,
            "--",
            "cmd",
            "/c",
            "type",
            &outside_file,
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block cmd /c type outside allowlist, output:\n{text}"
    );
    assert!(
        text.contains("absolute path argument") || text.contains("file argument"),
        "expected path-argument rejection, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_propagates_child_exit_code() {
    let output = nono_bin()
        .args(["run", "--", "cmd", "/c", "exit", "7"])
        .output()
        .expect("failed to run nono");

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected child exit code 7, output:\n{}",
        combined_output(&output)
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_honors_workdir() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let workdir = dir.path().to_string_lossy().into_owned();

    let output = nono_bin()
        .args(["run", "--workdir", &workdir, "--", "cmd", "/c", "cd"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows direct execution with workdir should succeed, output:\n{text}"
    );
    assert!(
        text.to_ascii_lowercase()
            .contains(&workdir.to_ascii_lowercase()),
        "expected child cwd in output, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_filters_dangerous_env_vars_and_keeps_safe_ones() {
    let output = nono_bin()
        .env("NODE_OPTIONS", "--require injected.js")
        .env("DOTNET_STARTUP_HOOKS", r"C:\malicious.dll")
        .env("NONO_TEST_SAFE_ENV", "kept")
        .args([
            "run",
            "--",
            "cmd",
            "/c",
            "echo SAFE=%NONO_TEST_SAFE_ENV% NODE=%NODE_OPTIONS% DOTNET=%DOTNET_STARTUP_HOOKS%",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        output.status.success(),
        "Windows env sanitization check should succeed, output:\n{text}"
    );
    assert!(
        text.contains("SAFE=kept"),
        "expected safe env var to survive, got:\n{text}"
    );
    assert!(
        text.contains("NODE=") && !text.contains("NODE=--require injected.js"),
        "expected NODE_OPTIONS to be filtered, got:\n{text}"
    );
    assert!(
        text.contains("DOTNET=") && !text.contains(r"DOTNET=C:\malicious.dll"),
        "expected DOTNET_STARTUP_HOOKS to be filtered, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_smoke_validates_stdout_stderr_and_exit_code() {
    let output = nono_bin()
        .args([
            "run",
            "--",
            "cmd",
            "/c",
            "echo stdout-line & echo stderr-line 1>&2 & exit 5",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(5),
        "expected child exit code 5, output:\n{text}"
    );
    assert!(
        text.contains("stdout-line"),
        "expected child stdout in output, got:\n{text}"
    );
    assert!(
        text.contains("stderr-line"),
        "expected child stderr in output, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_live_profile_restrictions() {
    let output = nono_bin()
        .args([
            "run",
            "--profile",
            "codex",
            "--",
            "cmd",
            "/c",
            "echo",
            "test",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block live profile-enforced execution, output:\n{text}"
    );
    assert!(
        text.contains("cannot enforce the requested sandbox controls"),
        "expected explicit preview enforcement error, got:\n{text}"
    );
    assert!(
        text.contains("preview limitation"),
        "expected preview wording in error, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_blocks_live_block_net_without_enforcement() {
    let output = nono_bin()
        .args(["run", "--block-net", "--", "cmd", "/c", "echo", "test"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview should block live network restriction requests, output:\n{text}"
    );
    assert!(
        text.contains("network"),
        "expected network restriction reason in error, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_supervised_preview_initializes_control_channel_scaffold() {
    let output = nono_bin()
        .args([
            "run",
            "--capability-elevation",
            "--no-audit",
            "--",
            "cmd",
            "/c",
            "echo",
            "test",
        ])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview rollback should stop after scaffold init, output:\n{text}"
    );
    assert!(
        text.contains("control channel scaffold"),
        "expected supervisor scaffold message, got:\n{text}"
    );
    assert!(
        text.contains("runtime capability elevation"),
        "expected requested supervised feature in message, got:\n{text}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_wrap_reports_preview_limitation() {
    let output = nono_bin()
        .args(["wrap", "--", "cmd", "/c", "echo", "test"])
        .output()
        .expect("failed to run nono");

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "Windows preview wrap should fail loudly, output:\n{text}"
    );
    assert!(
        text.contains("does not support `nono wrap` live execution"),
        "expected explicit wrap limitation, got:\n{text}"
    );
}
