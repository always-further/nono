param(
    [ValidateSet("build", "smoke", "integration", "security", "regression", "all")]
    [string]$Suite = "all",
    [string]$LogDir = "ci-logs"
)

$ErrorActionPreference = "Stop"
# Cargo and other native tools write normal progress output to stderr.
# Keep that from being promoted into terminating PowerShell errors while we tee logs.
$PSNativeCommandUseErrorActionPreference = $false

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Invoke-LoggedCargo {
    param(
        [string]$LogFile,
        [string]$Label,
        [string[]]$CargoArgs
    )

    $logPath = Join-Path $LogDir $LogFile
    "==> $Label" | Tee-Object -FilePath $logPath -Append
    "`$ cargo $($CargoArgs -join ' ')" | Tee-Object -FilePath $logPath -Append
    $stdoutPath = Join-Path $LogDir ([System.Guid]::NewGuid().ToString() + ".stdout.tmp")
    $stderrPath = Join-Path $LogDir ([System.Guid]::NewGuid().ToString() + ".stderr.tmp")
    $process = Start-Process -FilePath "cargo" `
        -ArgumentList $CargoArgs `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath
    foreach ($capturePath in @($stdoutPath, $stderrPath)) {
        if (Test-Path $capturePath) {
            Get-Content $capturePath | Tee-Object -FilePath $logPath -Append
            Remove-Item -LiteralPath $capturePath -Force
        }
    }
    if ($process.ExitCode -ne 0) {
        throw "Cargo command failed for $Label with exit code $($process.ExitCode)"
    }
    "" | Tee-Object -FilePath $logPath -Append | Out-Null
}

function Invoke-TestList {
    param(
        [string]$LogFile,
        [object[]]$Tests
    )

    foreach ($test in $Tests) {
        $pkg = $test.Package
        $filter = $test.Filter
        Invoke-LoggedCargo -LogFile $LogFile -Label "$pkg::$filter" -CargoArgs @(
            "test",
            "-p",
            $pkg,
            $filter,
            "--",
            "--nocapture"
        )
    }
}

function Invoke-LoggedCommand {
    param(
        [string]$LogFile,
        [string]$Label,
        [scriptblock]$Command
    )

    $logPath = Join-Path $LogDir $LogFile
    "==> $Label" | Tee-Object -FilePath $logPath -Append
    $capturePath = Join-Path $LogDir ([System.Guid]::NewGuid().ToString() + ".tmp")
    & $Command *> $capturePath
    if (Test-Path $capturePath) {
        Get-Content $capturePath | Tee-Object -FilePath $logPath -Append
        Remove-Item -LiteralPath $capturePath -Force
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed for $Label with exit code $LASTEXITCODE"
    }
    "" | Tee-Object -FilePath $logPath -Append | Out-Null
}

$smokeTests = @(
    @{ Package = "nono-cli"; Filter = "test_root_help_mentions_windows_restricted_execution_surface" },
    @{ Package = "nono-cli"; Filter = "windows_setup_check_only_reports_live_profile_subset" },
    @{ Package = "nono-cli"; Filter = "windows_setup_check_only_reports_unified_support_status" },
    @{ Package = "nono-cli"; Filter = "windows_run_executes_basic_command" },
    @{ Package = "nono-cli"; Filter = "windows_run_live_default_profile_executes_command" },
    @{ Package = "nono-cli"; Filter = "windows_shell_help_reports_documented_limitation" },
    @{ Package = "nono-cli"; Filter = "windows_wrap_help_reports_documented_limitation" }
)

$integrationTests = @(
    @{ Package = "nono-cli"; Filter = "windows_run_redirects_profile_state_vars_into_writable_allowlist" },
    @{ Package = "nono-cli"; Filter = "windows_run_honors_workdir" },
    @{ Package = "nono-cli"; Filter = "windows_run_live_codex_profile_fails_intentionally_with_backend_reason" },
    @{ Package = "nono-cli"; Filter = "windows_run_supervised_rollback_executes_command" },
    @{ Package = "nono-cli"; Filter = "windows_run_smoke_validates_stdout_stderr_and_exit_code" }
)

$securityTests = @(
    @{ Package = "nono"; Filter = "validate_preview_entry_point_rejects_shell" },
    @{ Package = "nono"; Filter = "validate_preview_entry_point_rejects_wrap" },
    @{ Package = "nono"; Filter = "validate_command_args_rejects_relative_parent_escape_outside_policy" },
    @{ Package = "nono"; Filter = "validate_command_args_rejects_symlink_escape_inside_policy" },
    @{ Package = "nono"; Filter = "validate_command_args_rejects_junction_escape_inside_policy" },
    @{ Package = "nono-cli"; Filter = "test_handle_windows_supervisor_message_rejects_duplicate_request_ids" },
    @{ Package = "nono-cli"; Filter = "test_handle_windows_supervisor_message_reports_open_url_limitation" },
    @{ Package = "nono-cli"; Filter = "windows_open_url_helper_reports_documented_limitation" },
    @{ Package = "nono-cli"; Filter = "windows_run_block_net_blocks_probe_connection" },
    @{ Package = "nono-cli"; Filter = "windows_run_block_net_cleans_up_promoted_wfp_filters_after_exit" }
)

$regressionTests = @(
    @{ Package = "nono"; Filter = "normalize_windows_path_strips_verbatim_prefix" },
    @{ Package = "nono"; Filter = "normalize_windows_path_strips_unc_verbatim_prefix" },
    @{ Package = "nono"; Filter = "windows_paths_start_with_case_insensitive_matches_drive_case" },
    @{ Package = "nono"; Filter = "low_integrity_compatible_dir_matches_localappdata_temp_low" },
    @{ Package = "nono-cli"; Filter = "windows_protected_path_check_handles_verbatim_prefix_and_case_insensitive_drive_letters" },
    @{ Package = "nono-cli"; Filter = "windows_path_overlaps_filter_handles_verbatim_prefix_and_drive_case" },
    @{ Package = "nono-cli"; Filter = "windows_run_prefers_managed_low_integrity_runtime_root_inside_allowlist" },
    @{ Package = "nono-cli"; Filter = "windows_run_ignores_unverified_localappdata_override_when_runtime_root_is_verified" },
    @{ Package = "nono-cli"; Filter = "windows_run_redirects_temp_vars_into_writable_allowlist" },
    @{ Package = "nono-cli"; Filter = "windows_run_redirects_profile_state_vars_into_writable_allowlist" },
    @{ Package = "nono-cli"; Filter = "config_with_valid_manifest_is_accepted" },
    @{ Package = "nono-cli"; Filter = "test_show_format_manifest_round_trip" }
)

$suites = if ($Suite -eq "all") {
    @("build", "smoke", "integration", "security", "regression")
} else {
    @($Suite)
}

foreach ($activeSuite in $suites) {
    switch ($activeSuite) {
        "build" {
            Invoke-LoggedCargo -LogFile "windows-build.log" -Label "build workspace" -CargoArgs @(
                "build",
                "--workspace",
                "--verbose"
            )
            Invoke-LoggedCommand -LogFile "windows-build.log" -Label "validate windows msi contract" -Command {
                & (Join-Path $PWD "scripts\validate-windows-msi-contract.ps1") -BinaryPath (Join-Path $PWD "target\debug\nono.exe")
            }
        }
        "smoke" {
            Invoke-TestList -LogFile "windows-smoke.log" -Tests $smokeTests
        }
        "integration" {
            Invoke-TestList -LogFile "windows-integration.log" -Tests $integrationTests
        }
        "security" {
            $wfpFilters = @(
                "windows_run_block_net_blocks_probe_connection",
                "windows_run_block_net_cleans_up_promoted_wfp_filters_after_exit"
            )
            $nonWfpTests = $securityTests | Where-Object { $_.Filter -notin $wfpFilters }
            $wfpTests = $securityTests | Where-Object { $_.Filter -in $wfpFilters }

            Invoke-TestList -LogFile "windows-security.log" -Tests $nonWfpTests

            if ($env:NONO_CI_HAS_WFP -eq 'true') {
                Invoke-TestList -LogFile "windows-security.log" -Tests $wfpTests
            } else {
                $msg = "SKIPPED: WFP tests require elevated runner (NONO_CI_HAS_WFP not set)"
                $msg | Tee-Object -FilePath (Join-Path $LogDir "windows-security.log") -Append
            }
        }
        "regression" {
            Invoke-TestList -LogFile "windows-regression.log" -Tests $regressionTests
        }
    }
}
