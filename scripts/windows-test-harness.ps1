param(
    [ValidateSet("build", "smoke", "integration", "security", "all")]
    [string]$Suite = "all",
    [string]$LogDir = "ci-logs"
)

$ErrorActionPreference = "Stop"

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
    & cargo @CargoArgs 2>&1 | Tee-Object -FilePath $logPath -Append
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo command failed for $Label with exit code $LASTEXITCODE"
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
    & $Command 2>&1 | Tee-Object -FilePath $logPath -Append
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed for $Label with exit code $LASTEXITCODE"
    }
    "" | Tee-Object -FilePath $logPath -Append | Out-Null
}

$smokeTests = @(
    @{ Package = "nono-cli"; Filter = "windows_root_help_reports_supported_subset_messaging" },
    @{ Package = "nono-cli"; Filter = "windows_setup_check_only_reports_live_profile_subset" },
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

$suites = if ($Suite -eq "all") {
    @("build", "smoke", "integration", "security")
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
            Invoke-TestList -LogFile "windows-security.log" -Tests $securityTests
        }
    }
}
