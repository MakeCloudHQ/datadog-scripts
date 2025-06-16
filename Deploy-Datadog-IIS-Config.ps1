# NinjaOne All-in-One Script: Install Datadog Agent & Configure IIS Monitoring

# $DatadogApiKey = "MY-API-KEY-IF-TESTING-LOCALLY"
# $DatadogSite = "datadoghq.eu"

Param(
    [Parameter(Mandatory=$true)]
    [string]$DatadogApiKey,

    [Parameter(Mandatory=$true)]
    [string]$DatadogSite
)

# --- Define Paths and Constants ---
$ddAgentInstallUrl = "https://windows-agent.datadoghq.com/datadog-agent-7-latest.amd64.msi"
$ddAgentInstallerPath = "$env:TEMP\datadog-agent-installer.msi"
$ddAgentService = "DatadogAgent"
$ddAgentConfDir = "C:\ProgramData\Datadog\conf.d"
$iisConfDir = Join-Path $ddAgentConfDir "iis.d"
$iisConfFile = Join-Path $iisConfDir "conf.yaml"
$datadogYamlPath = "C:\ProgramData\Datadog\datadog.yaml"
$iisLogsPath = "C:\inetpub\logs\LogFiles"
$ddAgentUser = "ddagentuser" # Default Datadog Agent service account

# --- Helper Function for Logging ---
function Write-Log {
    Param(
        [string]$Message,
        [string]$Level = "INFO" # INFO, WARNING, ERROR
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] [$Level] $Message"
    if ($Level -eq "ERROR") {
        Write-Error "[$Timestamp] [$Level] $Message"
        Exit 1 # Exit with error code if an error occurs
    }
}

Write-Log "Checking for Datadog Agent installation..."
try {
    if (-not (Get-Service -Name $ddAgentService -ErrorAction SilentlyContinue)) {
        Write-Log "Datadog Agent service not found. Proceeding with installation."

        # Download the installer
        Write-Log "Downloading Datadog Agent installer from $ddAgentInstallUrl..."
        Invoke-WebRequest -Uri $ddAgentInstallUrl -OutFile $ddAgentInstallerPath -ErrorAction Stop

        # Install the agent silently
        Write-Log "Installing Datadog Agent... This may take a few minutes."
        $installArgs = "/qn /i `"$ddAgentInstallerPath`" APIKEY=`"$DatadogApiKey`" SITE=`"$DatadogSite`""
        $process = Start-Process -FilePath "msiexec" -ArgumentList $installArgs -Wait -PassThru -ErrorAction Stop

        if ($process.ExitCode -eq 0) {
            Write-Log "Datadog Agent installed successfully."
            # Give service a moment to start
            Start-Sleep -Seconds 10
        } else {
            Write-Log "Datadog Agent installation failed with exit code: $($process.ExitCode)", "ERROR"
        }
    } else {
        Write-Log "Datadog Agent service found and running."
    }

    # Ensure the service is running after potential installation
    $serviceStatus = (Get-Service -Name $ddAgentService).Status
    if ($serviceStatus -ne "Running") {
        Write-Log "Datadog Agent service is not running. Attempting to start it...", "WARNING"
        Start-Service -Name $ddAgentService -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5 # Give it a moment
        $serviceStatus = (Get-Service -Name $ddAgentService).Status
        if ($serviceStatus -ne "Running") {
            Write-Log "Failed to start Datadog Agent service. Cannot proceed with configuration.", "ERROR"
        } else {
            Write-Log "Datadog Agent service started."
        }
    }

} catch {
    Write-Log "Error during Datadog Agent installation/check: $($_.Exception.Message)", "ERROR"
}

# --- 2. Configure logs_enabled via Environment Variable ---
Write-Log "Ensuring logs_enabled is true via system environment variable..."
try {
    # Check if the variable is already set to 'true'
    $currentValue = [System.Environment]::GetEnvironmentVariable("DD_LOGS_ENABLED", "Machine")
    if ($currentValue -ne "true") {
        Write-Log "Setting DD_LOGS_ENABLED=true as a system-wide environment variable."
        [System.Environment]::SetEnvironmentVariable("DD_LOGS_ENABLED", "true", "Machine")
        Write-Log "Environment variable set. A service restart is required to apply it."
        # The restart will happen at the end of the script
    } else {
        Write-Log "DD_LOGS_ENABLED environment variable is already correctly set."
    }
} catch {
    Write-Log "Error setting environment variable: $($_.Exception.Message)", "ERROR"
}

# --- 3. Configure IIS Integration (only if IIS is detected) ---
Write-Log "Checking for IIS role presence..."
if (Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue | Where-Object {$_.Installed}) {
    Write-Log "IIS role detected. Proceeding with IIS integration configuration."

    # Ensure the iis.d directory exists
    try {
        if (-not (Test-Path $iisConfDir)) {
            New-Item -Path $iisConfDir -ItemType Directory -Force | Out-Null
            Write-Log "Created directory: $iisConfDir"
        }

        # Content for iis.d\conf.yaml
        $iisConfigContent = @"
init_config:

instances:
  - host: "."
    # Uncomment and list specific sites if needed. Otherwise, all sites are monitored.
    # sites:
    #   - "Default Web Site"
    #   - "MyEcommerceSite"
    #   - "API_Service"

logs:
  - type: file
    path: C:\inetpub\logs\LogFiles\W3SVC*\u_ex*.log
    service: iis_websites
    source: iis
    sourcecategory: http_web_access
"@

        # Write the content to the conf.yaml file
        Set-Content -Path $iisConfFile -Value $iisConfigContent -Force
        Write-Log "Successfully wrote IIS integration configuration to $iisConfFile"

    } catch {
        Write-Log "Error during IIS integration configuration: $($_.Exception.Message)", "ERROR"
    }

    # --- 4. Set Permissions for IIS Logs ---
    Write-Log "Setting permissions for Datadog Agent on IIS log directory..."
    try {
        if (Test-Path $iisLogsPath) {
            # Get existing ACL
            $acl = Get-Acl $iisLogsPath
            # Define access rule for ddagentuser (Read, ReadAndExecute, ListDirectory)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ddAgentUser,
                "Read,ReadAndExecute,ListDirectory",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            # Add the rule
            $acl.AddAccessRule($rule)
            # Apply the updated ACL
            Set-Acl -Path $iisLogsPath -AclObject $acl -ErrorAction Stop
            Write-Log "Successfully set permissions on $iisLogsPath for $ddAgentUser."
        } else {
            Write-Log "IIS log directory ($iisLogsPath) not found. Cannot set permissions.", "WARNING"
        }
    } catch {
        Write-Log "Error setting permissions on IIS log directory: $($_.Exception.Message)", "ERROR"
    }

}

# --- 5. Restart Datadog Agent Service to apply all changes ---
Write-Log "Restarting Datadog Agent service to apply all configurations..."
try {
    Get-Service -Name $ddAgentService | Restart-Service -Force -ErrorAction Stop
    Start-Sleep -Seconds 10 # Give it ample time to restart
    $finalStatus = (Get-Service -Name $ddAgentService).Status
    if ($finalStatus -eq "Running") {
        Write-Log "Datadog Agent service successfully restarted and running ($finalStatus)."
        # Optional: Run a final status check and log it
        & "C:\Program Files\Datadog\Datadog Agent\bin\agent" status | Out-File -FilePath "$env:TEMP\datadog_final_status.log"
        Write-Log "Final Datadog Agent status logged to $env:TEMP\datadog_final_status.log"
    } else {
        Write-Log "Datadog Agent service did not restart successfully. Current status: $finalStatus", "ERROR"
    }
} catch {
    Write-Log "Error restarting Datadog Agent service: $($_.Exception.Message)", "ERROR"
}

Write-Log "Script execution completed."
Exit 0 # Indicate overall script success

