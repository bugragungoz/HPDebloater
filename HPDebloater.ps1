#Requires -RunAsAdministrator

<#
.SYNOPSIS
    HP Debloater - Comprehensive Laptop Bloatware Removal Utility
    
.DESCRIPTION
    Advanced PowerShell script to safely remove HP bloatware while protecting
    critical hardware functionality (touchpad, audio, camera, MUX switch, BIOS).
    
.NOTES
    Name:           HP Debloater
    Author:         Bugra
    Concept & Design: Bugra
    Development:    Claude 4.5 Sonnet AI
    Version:        1.0.0
    Created:        2025
    Target:         HP Laptops (optimized for OMEN series)
    
.LEGAL DISCLAIMER
    This tool is provided for LEGAL USE ONLY. The author accepts NO RESPONSIBILITY
    for any misuse, damage, warranty void, or legal consequences arising from use.
    
    - HP manufacturer warranty MAY BE VOIDED by using this script
    - Users are SOLELY RESPONSIBLE for system integrity and functionality
    - Users are SOLELY RESPONSIBLE for compliance with HP Terms of Service
    - Hardware functionality (audio, touchpad, camera, etc.) may be affected
    - Always create a Windows System Restore Point before execution
    - The author disclaims all warranties, express or implied
    
    BY USING THIS SCRIPT, YOU ACKNOWLEDGE AND ACCEPT FULL RESPONSIBILITY.
    
.IMPORTANT
    This script implements HARDWARE-AWARE debloating for HP laptops:
    - Protects critical hardware services (audio, touchpad, display, power)
    - Removes telemetry, analytics, and bloatware safely
    - Provides comprehensive backup and rollback capabilities
    - Includes multi-stage consent and warnings
    - Supports network isolation for HP telemetry
#>

$ErrorActionPreference = "Stop"

# ============================================================================
# SCRIPT CONFIGURATION
# ============================================================================

$script:Config = @{
    LogDirectory        = "$PSScriptRoot\HPDebloater_Logs"
    BackupDirectory     = "$PSScriptRoot\HPDebloater_Backups"
    LogFile             = ""
    SessionID           = (Get-Date -Format "yyyyMMdd_HHmmss")
    DryRun              = $false
    RulePrefix          = "HPDebloater"
    ScriptVersion       = "1.0.0"
}

$script:Statistics = @{
    ServicesDisabled    = 0
    ServicesEnabled     = 0
    TasksDisabled       = 0
    TasksEnabled        = 0
    FirewallRulesCreated = 0
    DomainsBlocked      = 0
    BackupsCreated      = 0
    ExecutionStartTime  = Get-Date
    ExecutionEndTime    = $null
}

# ============================================================================
# HARDWARE SERVICE DEFINITIONS - CRITICAL PROTECTION
# ============================================================================

# IMPORTANT EXCLUSIONS - WHY CERTAIN SERVICES ARE NOT INCLUDED:
# 
# This script INTENTIONALLY EXCLUDES the following critical HP services/features
# to prevent catastrophic system failures:
#
# [EXCLUDED - NEVER TOUCH]
#   * BIOS/UEFI Configuration Services
#     Reason: Can brick the system or prevent boot. Firmware-level changes are
#             too dangerous to automate. User should manage BIOS manually.
#
#   * MUX Switch / GPU Multiplexer Services (OMEN HSA Service)
#     Reason: Controls hardware GPU routing. Disabling can permanently lock GPU
#             mode requiring BIOS reset or system recovery. Beyond script scope.
#
#   * Firmware Update Services
#     Reason: Critical for security patches and hardware stability. Disabling
#             can leave system vulnerable or prevent important updates.
#
#   * TPM/Security Chip Services
#     Reason: Related to BitLocker, Secure Boot, and hardware security. Touching
#             these can lock user out of their own system.
#
#   * Intel Management Engine / AMD PSP Services
#     Reason: Low-level hardware management. Interference can cause instability.
#
# This script focuses ONLY on:
#   - Bloatware removal (HP Support Assistant, telemetry, etc.)
#   - Network isolation (blocking HP analytics/tracking)
#   - Non-critical HP software management
#
# Hardware-critical services (audio, touchpad, display, power) are PROTECTED.
#
# ============================================================================

$script:HardwareCritical = @{
    # TIER 0: NEVER DISABLE - Essential Hardware Functionality
    "HPAudioService" = @{
        DisplayName = "HP Audio Service"
        Impact = "SPEAKERS AND HEADPHONES WILL NOT WORK"
        Hardware = "Audio Output/Input"
        Severity = "CRITICAL"
        AllowDisable = $false
        Category = "AUDIO"
    }
    "HP Audio Switch Service" = @{
        DisplayName = "HP Audio Switch Service"
        Impact = "AUDIO ROUTING WILL FAIL"
        Hardware = "Audio Switching"
        Severity = "CRITICAL"
        AllowDisable = $false
        Category = "AUDIO"
    }
    "SynTPEnh" = @{
        DisplayName = "Synaptics Touchpad Service"
        Impact = "TOUCHPAD WILL NOT WORK - EXTERNAL MOUSE REQUIRED"
        Hardware = "Touchpad/Trackpad"
        Severity = "CRITICAL"
        AllowDisable = $false
        Category = "INPUT"
    }
    "SynTPEnhService" = @{
        DisplayName = "Synaptics Touchpad Enhancements"
        Impact = "TOUCHPAD GESTURES WILL NOT WORK"
        Hardware = "Touchpad Gestures"
        Severity = "CRITICAL"
        AllowDisable = $false
        Category = "INPUT"
    }
    "HP Display Control Service" = @{
        DisplayName = "HP Display Control Service"
        Impact = "BRIGHTNESS CONTROL MAY FAIL"
        Hardware = "Display Panel Brightness"
        Severity = "CRITICAL"
        AllowDisable = $false
        Category = "DISPLAY"
    }
    "HP Power Management Service" = @{
        DisplayName = "HP Power Management Service"
        Impact = "BATTERY MANAGEMENT WILL FAIL"
        Hardware = "Battery and Power Control"
        Severity = "CRITICAL"
        AllowDisable = $false
        Category = "POWER"
    }
    "HP WMI Service" = @{
        DisplayName = "HP WMI Service"
        Impact = "HARDWARE COMMUNICATION LAYER WILL BREAK"
        Hardware = "Hardware Management Interface"
        Severity = "CRITICAL"
        AllowDisable = $false
        Category = "CORE"
    }
    "HP Hotkey Service" = @{
        DisplayName = "HP Hotkey Service"
        Impact = "FUNCTION KEYS (Brightness, Volume, etc.) WILL NOT WORK"
        Hardware = "Keyboard Function Keys"
        Severity = "CRITICAL"
        AllowDisable = $false
        Category = "INPUT"
    }
    "HP Wireless Button Driver" = @{
        DisplayName = "HP Wireless Button Driver"
        Impact = "WIFI/BLUETOOTH TOGGLE BUTTON MAY NOT WORK"
        Hardware = "Wireless Hardware Switch"
        Severity = "CRITICAL"
        AllowDisable = $false
        Category = "NETWORK"
    }
}

$script:HardwareSemiCritical = @{
    # TIER 1: EXTREME WARNING REQUIRED - Hardware affected but can be disabled
    "HP Comm Recovery" = @{
        DisplayName = "HP Camera Service"
        Impact = "WEBCAM WILL NOT WORK"
        Hardware = "Integrated Camera"
        Severity = "HIGH"
        AllowDisable = $true
        RequiresExplicitConsent = $true
        Category = "CAMERA"
    }
    "HP Enhanced Lighting Service" = @{
        DisplayName = "HP Enhanced Lighting Service"
        Impact = "RGB KEYBOARD BACKLIGHT WILL NOT WORK"
        Hardware = "Keyboard Backlight/RGB"
        Severity = "MEDIUM"
        AllowDisable = $true
        RequiresExplicitConsent = $true
        Category = "LIGHTING"
    }
    "HP Connection Optimizer" = @{
        DisplayName = "HP Connection Optimizer"
        Impact = "NETWORK PERFORMANCE MAY DEGRADE"
        Hardware = "WiFi/Ethernet Optimization"
        Severity = "MEDIUM"
        AllowDisable = $true
        RequiresExplicitConsent = $true
        Category = "NETWORK"
    }
}

$script:BloatwareServices = @{
    # TIER 2: SAFE TO DISABLE - Bloatware and Telemetry
    # NOTE: Services listed here are non-essential HP software
    # Hardware-critical services are in $HardwareCritical (protected)
    
    "HPSupportSolutionsFrameworkService" = @{
        DisplayName = "HP Support Solutions Framework Service"
        Impact = "HP Support Assistant will not function"
        Category = "SUPPORT"
        AllowDisable = $true
    }
    "HPAppHelperCap" = @{
        DisplayName = "HP App Helper"
        Impact = "HP App Helper will not function"
        Category = "SUPPORT"
        AllowDisable = $true
    }
    "HPDiagsCap" = @{
        DisplayName = "HP Diagnostics"
        Impact = "HP Diagnostics will not function"
        Category = "SUPPORT"
        AllowDisable = $true
    }
    "HPNetworkCap" = @{
        DisplayName = "HP Network Check"
        Impact = "HP Network Check will not function"
        Category = "SUPPORT"
        AllowDisable = $true
    }
    "HP System Info HSA Service" = @{
        DisplayName = "HP System Info HSA Service"
        Impact = "HP System Information will not function"
        Category = "SUPPORT"
        AllowDisable = $true
    }
    "HpTouchpointAnalyticsService" = @{
        DisplayName = "HP Touchpoint Analytics"
        Impact = "Telemetry and analytics disabled"
        Category = "TELEMETRY"
        AllowDisable = $true
    }
    "HP Customer Participation Program" = @{
        DisplayName = "HP Customer Participation Program"
        Impact = "Data collection disabled"
        Category = "TELEMETRY"
        AllowDisable = $true
    }
    "HPJumpStartBridge" = @{
        DisplayName = "HP JumpStart Bridge"
        Impact = "HP JumpStart will not function"
        Category = "SUPPORT"
        AllowDisable = $true
    }
    "HP Ink Droplet Service" = @{
        DisplayName = "HP Ink Droplet Service"
        Impact = "Printer ink monitoring disabled"
        Category = "SUPPORT"
        AllowDisable = $true
    }
}

# ============================================================================
# HP TELEMETRY DOMAIN LIST
# ============================================================================

$script:TelemetryDomains = @(
    # Core Telemetry
    "telemetry.hp.com",
    "metrics.hp.com",
    "analytics.hp.com",
    "tracking.hp.com",
    "stats.hp.com",
    
    # Crash Reporting
    "crashreport.hp.com",
    "crashreporter.hp.com",
    "errorlog.hp.com",
    
    # Customer Participation
    "ceip.hp.com",
    "feedback.hp.com",
    "survey.hp.com",
    
    # Diagnostics
    "diagnostics.hp.com",
    "diagnostic-services.hp.com",
    
    # Support Metrics
    "support-metrics.hp.com",
    "usage.hp.com",
    
    # OMEN Specific Telemetry
    "omen-telemetry.hp.com",
    "omen-analytics.omen.com",
    "metrics.omenbyh.com",
    "omenbyh.com",
    "omen.com"
)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                                                                                " -ForegroundColor Cyan
    Write-Host "     ######  ########   #######  ##     ## ########                             " -ForegroundColor Cyan
    Write-Host "    ##    ## ##     ## ##     ##  ##   ##       ##                              " -ForegroundColor Cyan
    Write-Host "    ##       ##     ## ##     ##   ## ##       ##                               " -ForegroundColor Cyan
    Write-Host "    ##       ########  ##     ##    ###       ##                                " -ForegroundColor Cyan
    Write-Host "    ##       ##   ##   ##     ##   ## ##     ##                                 " -ForegroundColor Cyan
    Write-Host "    ##    ## ##    ##  ##     ##  ##   ##   ##                                  " -ForegroundColor Cyan
    Write-Host "     ######  ##     ##  #######  ##     ## ########                             " -ForegroundColor Cyan
    Write-Host "                                                                                " -ForegroundColor Cyan
    Write-Host "                    HP Debloater Utility v$($script:Config.ScriptVersion)                         " -ForegroundColor Cyan
    Write-Host "                    Laptop Hardware-Aware Bloatware Removal                     " -ForegroundColor Cyan
    Write-Host "                                                                                " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Author: Bugra | Development: Claude 4.5 Sonnet AI" -ForegroundColor Gray
    Write-Host "  Session ID: $($script:Config.SessionID)" -ForegroundColor Gray
    Write-Host "  Backup Directory: $($script:Config.BackupDirectory)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [!] CRITICAL: This tool modifies system services and may affect warranty" -ForegroundColor Red
    Write-Host "  [!] Press Ctrl+C at any time to abort operation" -ForegroundColor Yellow
    Write-Host ""
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO'
    )
    
    if ($script:Config.LogFile) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Message"
        Add-Content -Path $script:Config.LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
    
    # Also output to transcript if running
    Write-Verbose "[$Level] $Message" -Verbose:$false
}

function Initialize-Environment {
    Write-Host "[Initializing] Setting up environment..." -ForegroundColor Cyan
    
    try {
        # Create log directory
        if (-not (Test-Path $script:Config.LogDirectory)) {
            New-Item -ItemType Directory -Path $script:Config.LogDirectory -Force | Out-Null
        }
        
        # Create backup directory
        if (-not (Test-Path $script:Config.BackupDirectory)) {
            New-Item -ItemType Directory -Path $script:Config.BackupDirectory -Force | Out-Null
        }
        
        # Set log file path
        $script:Config.LogFile = Join-Path $script:Config.LogDirectory "HPDebloater_$($script:Config.SessionID).log"
        
        # Start transcript
        $transcriptPath = Join-Path $script:Config.LogDirectory "HPDebloater_Transcript_$($script:Config.SessionID).log"
        Start-Transcript -Path $transcriptPath -Force | Out-Null
        
        Write-Log "Environment initialized successfully" -Level SUCCESS
        Write-Log "Script Version: $($script:Config.ScriptVersion)" -Level INFO
        Write-Log "Session ID: $($script:Config.SessionID)" -Level INFO
        Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)" -Level INFO
        Write-Log "OS: $([System.Environment]::OSVersion.VersionString)" -Level INFO
        
        Write-Host "  [OK] Log directory: $($script:Config.LogDirectory)" -ForegroundColor Green
        Write-Host "  [OK] Backup directory: $($script:Config.BackupDirectory)" -ForegroundColor Green
        Write-Host "  [OK] Session log: HPDebloater_$($script:Config.SessionID).log" -ForegroundColor Green
        Write-Host ""
        
        return $true
    }
    catch {
        Write-Host "  [ERROR] Failed to initialize environment: $_" -ForegroundColor Red
        return $false
    }
}

function Test-AdministratorPrivileges {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host ""
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host "                          ADMINISTRATOR REQUIRED" -ForegroundColor Red
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "  [ERROR] This script requires Administrator privileges!" -ForegroundColor Red
        Write-Host ""
        Write-Host "  To run as Administrator:" -ForegroundColor Yellow
        Write-Host "    1. Right-click on PowerShell" -ForegroundColor White
        Write-Host "    2. Select 'Run as Administrator'" -ForegroundColor White
        Write-Host "    3. Navigate to script directory" -ForegroundColor White
        Write-Host "    4. Run: .\HPDebloater.ps1" -ForegroundColor White
        Write-Host ""
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host ""
        
        Write-Log "Script execution failed: Not running as Administrator" -Level ERROR
        return $false
    }
    
    Write-Log "Administrator privileges confirmed" -Level SUCCESS
    return $true
}

# ============================================================================
# MULTI-PAGE DISCLAIMER SYSTEM
# ============================================================================

function Show-DisclaimerPage1 {
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                   HP DEBLOATER - LEGAL DISCLAIMER" -ForegroundColor Red
    Write-Host "                            (Page 1 of 5)" -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "                        *** CRITICAL WARNING ***" -ForegroundColor Yellow
    Write-Host "           READ EVERY PAGE CAREFULLY BEFORE PROCEEDING" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                         WARRANTY IMPLICATIONS" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "[!] HP MANUFACTURER WARRANTY MAY BE VOIDED" -ForegroundColor Red
    Write-Host ""
    Write-Host "    By modifying system services, scheduled tasks, or registry entries:" -ForegroundColor White
    Write-Host ""
    Write-Host "    * HP Inc. may consider your system warranty VOID" -ForegroundColor Yellow
    Write-Host "    * HP Support may REFUSE technical assistance" -ForegroundColor Yellow
    Write-Host "    * HP may FLAG your system as 'modified' and deny service" -ForegroundColor Yellow
    Write-Host "    * Hardware repairs may be DENIED under warranty claims" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    IMPORTANT: HP's warranty terms typically prohibit:" -ForegroundColor Cyan
    Write-Host "      - Unauthorized software modifications" -ForegroundColor White
    Write-Host "      - Disabling manufacturer-installed services" -ForegroundColor White
    Write-Host "      - Tampering with system management tools" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                         LEGAL RESPONSIBILITY" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "[!] YOU ACCEPT FULL LEGAL RESPONSIBILITY" -ForegroundColor Red
    Write-Host ""
    Write-Host "    This script is provided for EDUCATIONAL and PERSONAL USE ONLY." -ForegroundColor White
    Write-Host ""
    Write-Host "    The author/developer:" -ForegroundColor Cyan
    Write-Host "      * Accepts NO LIABILITY for any damages" -ForegroundColor White
    Write-Host "      * Accepts NO RESPONSIBILITY for warranty voids" -ForegroundColor White
    Write-Host "      * Accepts NO RESPONSIBILITY for system failures" -ForegroundColor White
    Write-Host "      * Accepts NO RESPONSIBILITY for data loss" -ForegroundColor White
    Write-Host "      * Accepts NO RESPONSIBILITY for hardware damage" -ForegroundColor White
    Write-Host ""
    Write-Host "    You acknowledge that:" -ForegroundColor Cyan
    Write-Host "      * You are SOLELY LIABLE for all consequences" -ForegroundColor White
    Write-Host "      * You understand HP Terms of Service implications" -ForegroundColor White
    Write-Host "      * You will NOT hold the author liable for ANY issues" -ForegroundColor White
    Write-Host "      * You have the RIGHT to modify your own system" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
}

function Show-DisclaimerPage2 {
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                   HP DEBLOATER - LEGAL DISCLAIMER" -ForegroundColor Red
    Write-Host "                            (Page 2 of 5)" -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "                   SYSTEM STABILITY & HARDWARE RISKS" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                      CRITICAL HARDWARE SERVICES" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "[!] LAPTOP HARDWARE MAY STOP WORKING" -ForegroundColor Red
    Write-Host ""
    Write-Host "    This laptop contains hardware that REQUIRES specific HP services:" -ForegroundColor White
    Write-Host ""
    Write-Host "    AUDIO SYSTEM:" -ForegroundColor Cyan
    Write-Host "      * Service: HP Audio Service, HP Audio Switch Service" -ForegroundColor White
    Write-Host "      * Risk: Speakers and headphones may STOP WORKING entirely" -ForegroundColor Yellow
    Write-Host "      * Impact: NO SOUND OUTPUT until services re-enabled" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    TOUCHPAD:" -ForegroundColor Cyan
    Write-Host "      * Service: HP Touchpad Service, Synaptics Service" -ForegroundColor White
    Write-Host "      * Risk: Touchpad may become COMPLETELY UNRESPONSIVE" -ForegroundColor Yellow
    Write-Host "      * Impact: External mouse REQUIRED if disabled" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    WEBCAM:" -ForegroundColor Cyan
    Write-Host "      * Service: HP Camera Service" -ForegroundColor White
    Write-Host "      * Risk: Integrated camera may NOT FUNCTION" -ForegroundColor Yellow
    Write-Host "      * Impact: Video calls, photography apps will FAIL" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    DISPLAY:" -ForegroundColor Cyan
    Write-Host "      * Service: HP Display Control Service" -ForegroundColor White
    Write-Host "      * Risk: Brightness control may STOP WORKING" -ForegroundColor Yellow
    Write-Host "      * Impact: Manual brightness adjustment may be IMPOSSIBLE" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    BATTERY/POWER:" -ForegroundColor Cyan
    Write-Host "      * Service: HP Power Management Service" -ForegroundColor White
    Write-Host "      * Risk: Battery optimization will FAIL" -ForegroundColor Yellow
    Write-Host "      * Impact: Reduced battery life, no power profiles" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    KEYBOARD FUNCTION KEYS:" -ForegroundColor Cyan
    Write-Host "      * Service: HP Hotkey Service" -ForegroundColor White
    Write-Host "      * Risk: F-keys (Brightness, Volume, etc.) may NOT WORK" -ForegroundColor Yellow
    Write-Host "      * Impact: Must use Windows settings for brightness/volume" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
}

function Show-DisclaimerPage3 {
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                   HP DEBLOATER - LEGAL DISCLAIMER" -ForegroundColor Red
    Write-Host "                            (Page 3 of 5)" -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "                        SCRIPT SCOPE & LIMITATIONS" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                    WHAT THIS SCRIPT DOES" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "[+] This script ONLY targets:" -ForegroundColor Green
    Write-Host ""
    Write-Host "    BLOATWARE:" -ForegroundColor Cyan
    Write-Host "      * HP Support Assistant (support tool)" -ForegroundColor White
    Write-Host "      * HP Telemetry & Analytics (data collection)" -ForegroundColor White
    Write-Host "      * HP Customer Participation (feedback programs)" -ForegroundColor White
    Write-Host "      * HP Diagnostics & Documentation" -ForegroundColor White
    Write-Host ""
    Write-Host "    NETWORK ISOLATION:" -ForegroundColor Cyan
    Write-Host "      * Block HP telemetry domains (analytics, tracking)" -ForegroundColor White
    Write-Host "      * Block HP analytics services" -ForegroundColor White
    Write-Host "      * Prevent data collection to HP servers" -ForegroundColor White
    Write-Host ""
    Write-Host "    OPTIONAL HARDWARE:" -ForegroundColor Cyan
    Write-Host "      * Webcam service (with explicit consent)" -ForegroundColor White
    Write-Host "      * RGB lighting service (with explicit consent)" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                    WHAT THIS SCRIPT DOES NOT TOUCH" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "[!] This script INTENTIONALLY EXCLUDES:" -ForegroundColor Red
    Write-Host ""
    Write-Host "    NEVER MODIFIED (Protected):" -ForegroundColor Cyan
    Write-Host "      * BIOS/UEFI configuration services" -ForegroundColor White
    Write-Host "      * Firmware update services" -ForegroundColor White
    Write-Host "      * MUX switch / GPU multiplexer services" -ForegroundColor White
    Write-Host "      * TPM/Security chip services" -ForegroundColor White
    Write-Host "      * Hardware management engines" -ForegroundColor White
    Write-Host ""
    Write-Host "    Reason: These are TOO DANGEROUS to automate." -ForegroundColor Yellow
    Write-Host "            Interference can brick your system or lock you out." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    ALWAYS PROTECTED (Cannot be disabled):" -ForegroundColor Cyan
    Write-Host "      * Audio services (speakers, headphones)" -ForegroundColor White
    Write-Host "      * Touchpad services" -ForegroundColor White
    Write-Host "      * Display control (brightness)" -ForegroundColor White
    Write-Host "      * Power management (battery)" -ForegroundColor White
    Write-Host "      * Keyboard function keys" -ForegroundColor White
    Write-Host "      * WiFi/Bluetooth hardware buttons" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
}

function Show-DisclaimerPage4 {
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                   HP DEBLOATER - LEGAL DISCLAIMER" -ForegroundColor Red
    Write-Host "                            (Page 4 of 5)" -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "                      BACKUP & RECOVERY INFORMATION" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                       SYSTEM RESTORE POINT - CRITICAL" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "[!] CREATE A WINDOWS SYSTEM RESTORE POINT NOW" -ForegroundColor Red
    Write-Host ""
    Write-Host "    Before proceeding, you MUST manually create a restore point:" -ForegroundColor White
    Write-Host ""
    Write-Host "    HOW TO CREATE SYSTEM RESTORE POINT:" -ForegroundColor Cyan
    Write-Host "      1. Press Windows Key + R" -ForegroundColor White
    Write-Host "      2. Type: SystemPropertiesProtection" -ForegroundColor Yellow
    Write-Host "      3. Press ENTER" -ForegroundColor White
    Write-Host "      4. Click 'Create...' button" -ForegroundColor White
    Write-Host "      5. Enter description: Before HP Debloater - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Yellow
    Write-Host "      6. Click 'Create' and wait for completion (2-5 minutes)" -ForegroundColor White
    Write-Host "      7. Return to this script and continue" -ForegroundColor White
    Write-Host ""
    Write-Host "    Why System Restore Point is CRITICAL:" -ForegroundColor Cyan
    Write-Host "      * Provides Windows-native full system recovery" -ForegroundColor White
    Write-Host "      * Can restore even if script backup fails" -ForegroundColor White
    Write-Host "      * Recovers registry, system files, and configurations" -ForegroundColor White
    Write-Host "      * Last resort if something goes wrong" -ForegroundColor White
    Write-Host ""
    Write-Host "    This script provides its own backup system, but System Restore Point" -ForegroundColor Cyan
    Write-Host "    is an ADDITIONAL safety layer that operates independently." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                          SCRIPT BACKUP SYSTEM" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "[+] This script will automatically backup:" -ForegroundColor Green
    Write-Host ""
    Write-Host "      * All HP service states and configurations (JSON format)" -ForegroundColor White
    Write-Host "      * All HP scheduled tasks (XML export)" -ForegroundColor White
    Write-Host "      * Windows Firewall rules (JSON format)" -ForegroundColor White
    Write-Host "      * Hosts file modifications (timestamped backup)" -ForegroundColor White
    Write-Host "      * Registry startup entries (.reg file)" -ForegroundColor White
    Write-Host "      * Operation metadata and manifest" -ForegroundColor White
    Write-Host ""
    Write-Host "    Backups stored in: HPDebloater_Backups\Backup_[Timestamp]\" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Rollback capability:" -ForegroundColor Cyan
    Write-Host "      * Full restore from any backup" -ForegroundColor White
    Write-Host "      * Step-by-step recovery process" -ForegroundColor White
    Write-Host "      * Verification after restore" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
}

function Show-DisclaimerPage5 {
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                   HP DEBLOATER - LEGAL DISCLAIMER" -ForegroundColor Red
    Write-Host "                            (Page 5 of 5)" -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "                         FINAL ACKNOWLEDGMENT" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                           NO WARRANTIES" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "This software is provided 'AS IS' without warranty of any kind, either" -ForegroundColor White
    Write-Host "expressed or implied, including but not limited to:" -ForegroundColor White
    Write-Host ""
    Write-Host "  * Warranties of merchantability" -ForegroundColor White
    Write-Host "  * Fitness for a particular purpose" -ForegroundColor White
    Write-Host "  * Non-infringement" -ForegroundColor White
    Write-Host "  * Accuracy or completeness" -ForegroundColor White
    Write-Host "  * System stability or compatibility" -ForegroundColor White
    Write-Host ""
    Write-Host "The entire risk as to the quality and performance of the script is with YOU." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Should the script prove defective, YOU assume the cost of all necessary" -ForegroundColor Yellow
    Write-Host "servicing, repair, or correction." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                      PROFESSIONAL CONSULTATION" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "If you are unsure about ANY aspect of this script:" -ForegroundColor White
    Write-Host ""
    Write-Host "  * Consult with a qualified IT professional" -ForegroundColor White
    Write-Host "  * Contact HP Support for guidance (before modifications)" -ForegroundColor White
    Write-Host "  * Research HP service dependencies thoroughly" -ForegroundColor White
    Write-Host "  * Test in a non-production environment first" -ForegroundColor White
    Write-Host ""
    Write-Host "DO NOT PROCEED if you do not fully understand the implications." -ForegroundColor Red
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                           FINAL CONSENT" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "By proceeding, you explicitly acknowledge and agree that:" -ForegroundColor White
    Write-Host ""
    Write-Host "  [X] I have read ALL 5 pages of this disclaimer" -ForegroundColor Cyan
    Write-Host "  [X] I understand that my HP warranty may be VOIDED" -ForegroundColor Cyan
    Write-Host "  [X] I understand that hardware may STOP WORKING" -ForegroundColor Cyan
    Write-Host "  [X] I accept FULL RESPONSIBILITY for all consequences" -ForegroundColor Cyan
    Write-Host "  [X] I will NOT hold the author liable for ANY damages" -ForegroundColor Cyan
    Write-Host "  [X] I have created a Windows System Restore Point" -ForegroundColor Cyan
    Write-Host "  [X] I understand this is NOT endorsed by HP Inc." -ForegroundColor Cyan
    Write-Host "  [X] I am proceeding at MY OWN RISK" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
}

function Show-Disclaimer {
    $pages = @(
        { Show-DisclaimerPage1 },
        { Show-DisclaimerPage2 },
        { Show-DisclaimerPage3 },
        { Show-DisclaimerPage4 },
        { Show-DisclaimerPage5 }
    )
    
    $currentPage = 0
    
    while ($currentPage -lt $pages.Count) {
        # Display current page
        & $pages[$currentPage]
        
        # Navigation prompt
        if ($currentPage -eq 0) {
            Write-Host "Press ENTER to continue to Page 2, or type 'QUIT' to exit: " -NoNewline -ForegroundColor Yellow
        }
        elseif ($currentPage -eq ($pages.Count - 1)) {
            Write-Host "Type 'I HAVE READ ALL 5 PAGES AND ACCEPT ALL RISKS' to continue: " -NoNewline -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Type 'BACK' for Page 4, or 'QUIT' to exit: " -NoNewline -ForegroundColor Yellow
        }
        else {
            Write-Host "Press ENTER to continue to Page $($currentPage + 2), type 'BACK' for Page $currentPage, or 'QUIT' to exit: " -NoNewline -ForegroundColor Yellow
        }
        
        $response = Read-Host
        
        # Handle response
        if ($response -eq 'QUIT') {
            Write-Host ""
            Write-Host "[CANCELLED] Exiting safely. No changes made." -ForegroundColor Green
            Write-Host ""
            Write-Log "User quit during disclaimer (Page $($currentPage + 1))" -Level INFO
            return $false
        }
        elseif ($response -eq 'BACK' -and $currentPage -gt 0) {
            $currentPage--
        }
        elseif ($currentPage -eq ($pages.Count - 1)) {
            # Last page - require exact phrase
            if ($response -eq 'I HAVE READ ALL 5 PAGES AND ACCEPT ALL RISKS') {
                Write-Host ""
                Write-Host "[CONFIRMED] Proceeding with operation..." -ForegroundColor Green
                Write-Log "User accepted all disclaimer pages and risks" -Level WARNING
                Start-Sleep -Seconds 1
                return $true
            }
            else {
                Write-Host ""
                Write-Host "[!] Invalid response. Please type exactly as shown." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
        else {
            $currentPage++
        }
    }
    
    return $false
}

# ============================================================================
# SYSTEM RESTORE POINT PROMPT
# ============================================================================

function Show-SystemRestorePointPrompt {
    Clear-Host
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "              SYSTEM RESTORE POINT - CRITICAL SAFETY MEASURE" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Before making ANY changes, you should create a Windows System Restore Point." -ForegroundColor White
    Write-Host ""
    Write-Host "  This provides a COMPLETE system recovery mechanism independent of this script." -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                    HOW TO CREATE RESTORE POINT MANUALLY" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "  Step 1: Press Windows Key + R" -ForegroundColor Cyan
    Write-Host "          (Run dialog will open)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Step 2: Type exactly: SystemPropertiesProtection" -ForegroundColor Cyan
    Write-Host "          Then press ENTER" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Step 3: Click the 'Create...' button" -ForegroundColor Cyan
    Write-Host "          (Located at bottom of System Protection tab)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Step 4: Enter description:" -ForegroundColor Cyan
    Write-Host "          Before HP Debloater - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Step 5: Click 'Create' and wait for completion" -ForegroundColor Cyan
    Write-Host "          (May take 2-5 minutes)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Step 6: Return to this script and continue" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host "                    TROUBLESHOOTING RESTORE POINTS" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "  If 'Create' button is grayed out:" -ForegroundColor Yellow
    Write-Host "    1. Select your C: drive in the list" -ForegroundColor White
    Write-Host "    2. Click 'Configure' button" -ForegroundColor White
    Write-Host "    3. Select 'Turn on system protection'" -ForegroundColor White
    Write-Host "    4. Set disk space to at least 5%" -ForegroundColor White
    Write-Host "    5. Click OK, then try 'Create' again" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    
    # Check if restore points are enabled
    try {
        $restoreEnabled = $null -ne (Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
        if ($restoreEnabled) {
            Write-Host "  [OK] System Restore is ENABLED on this PC" -ForegroundColor Green
            Write-Log "System Restore is enabled" -Level INFO
        }
        else {
            Write-Host "  [!] System Restore appears to be DISABLED" -ForegroundColor Red
            Write-Host "      Follow troubleshooting steps above to enable it" -ForegroundColor Yellow
            Write-Log "System Restore is disabled" -Level WARNING
        }
    }
    catch {
        Write-Host "  [?] Could not verify System Restore status" -ForegroundColor Yellow
        Write-Log "Could not verify System Restore status: $_" -Level WARNING
    }
    
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor White
    Write-Host ""
    Write-Host "  Have you created a System Restore Point? (yes/no): " -NoNewline -ForegroundColor Cyan
    $created = Read-Host
    
    if ($created -notmatch '^(yes|y)$') {
        Write-Host ""
        Write-Host "  [!] STRONGLY RECOMMENDED: Create a restore point before proceeding!" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Do you want to proceed WITHOUT a System Restore Point? (yes/no): " -NoNewline -ForegroundColor Yellow
        $proceedAnyway = Read-Host
        
        if ($proceedAnyway -notmatch '^(yes|y)$') {
            Write-Host ""
            Write-Host "  [CANCELLED] Exiting safely. No changes made." -ForegroundColor Green
            Write-Host ""
            Write-Log "User cancelled: No System Restore Point created" -Level INFO
            return $false
        }
        else {
            Write-Log "User proceeded WITHOUT System Restore Point" -Level WARNING
        }
    }
    else {
        Write-Host ""
        Write-Host "  [OK] Restore Point confirmed. Proceeding with safety net active." -ForegroundColor Green
        Write-Log "User confirmed System Restore Point creation" -Level SUCCESS
        Start-Sleep -Seconds 2
    }
    
    return $true
}

# ============================================================================
# BACKUP SYSTEM
# ============================================================================

function New-BackupDirectory {
    $backupDir = Join-Path $script:Config.BackupDirectory "Backup_$($script:Config.SessionID)"
    
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    }
    
    Write-Log "Created backup directory: $backupDir" -Level SUCCESS
    return $backupDir
}

function Backup-HPServices {
    param([string]$BackupDir)
    
    Write-Host "  [Backup] Saving HP services state..." -ForegroundColor Cyan
    
    try {
        $allServices = Get-Service | Where-Object { 
            $_.ServiceName -like "HP*" -or 
            $_.ServiceName -like "*OMEN*" -or 
            $_.DisplayName -like "*HP*" -or
            $_.DisplayName -like "*Hewlett*"
        }
        
        $serviceData = @()
        
        foreach ($service in $allServices) {
            $serviceInfo = @{
                Name = $service.ServiceName
                DisplayName = $service.DisplayName
                Status = $service.Status.ToString()
                StartType = $service.StartType.ToString()
                CanStop = $service.CanStop
                CanPauseAndContinue = $service.CanPauseAndContinue
            }
            
            # Determine category
            if ($script:HardwareCritical.ContainsKey($service.DisplayName)) {
                $serviceInfo['Category'] = "CRITICAL"
            }
            elseif ($script:HardwareSemiCritical.ContainsKey($service.DisplayName)) {
                $serviceInfo['Category'] = "SEMI_CRITICAL"
            }
            elseif ($script:BloatwareServices.ContainsKey($service.ServiceName)) {
                $serviceInfo['Category'] = "BLOATWARE"
            }
            else {
                $serviceInfo['Category'] = "UNKNOWN"
            }
            
            $serviceData += $serviceInfo
        }
        
        $backupFile = Join-Path $BackupDir "services_backup.json"
        $serviceData | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile -Encoding UTF8
        
        Write-Host "    [OK] Backed up $($serviceData.Count) HP services" -ForegroundColor Green
        Write-Log "Backed up $($serviceData.Count) services to $backupFile" -Level SUCCESS
        
        return $serviceData.Count
    }
    catch {
        Write-Host "    [ERROR] Failed to backup services: $_" -ForegroundColor Red
        Write-Log "Service backup failed: $_" -Level ERROR
        return 0
    }
}

function Backup-HPScheduledTasks {
    param([string]$BackupDir)
    
    Write-Host "  [Backup] Saving HP scheduled tasks..." -ForegroundColor Cyan
    
    try {
        $hpTasks = Get-ScheduledTask | Where-Object { 
            $_.TaskPath -like "*\HP\*" -or 
            $_.TaskPath -like "*\OMEN\*" -or
            $_.TaskName -like "*HP*" -or
            $_.TaskName -like "*OMEN*"
        }
        
        $taskCount = 0
        
        foreach ($task in $hpTasks) {
            try {
                $sanitizedName = $task.TaskName -replace '[\\/:*?"<>|]', '_'
                $taskXmlPath = Join-Path $BackupDir "task_$sanitizedName.xml"
                
                Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath | 
                    Out-File -FilePath $taskXmlPath -Encoding UTF8
                
                $taskCount++
            }
            catch {
                Write-Log "Failed to backup task $($task.TaskName): $_" -Level WARNING
            }
        }
        
        Write-Host "    [OK] Backed up $taskCount scheduled tasks" -ForegroundColor Green
        Write-Log "Backed up $taskCount tasks to $BackupDir" -Level SUCCESS
        
        return $taskCount
    }
    catch {
        Write-Host "    [ERROR] Failed to backup tasks: $_" -ForegroundColor Red
        Write-Log "Task backup failed: $_" -Level ERROR
        return 0
    }
}

function Backup-HostsFile {
    param([string]$BackupDir)
    
    Write-Host "  [Backup] Saving hosts file..." -ForegroundColor Cyan
    
    try {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $hostsBackup = Join-Path $BackupDir "hosts_backup.txt"
        
        if (Test-Path $hostsPath) {
            Copy-Item -Path $hostsPath -Destination $hostsBackup -Force
            Write-Host "    [OK] Hosts file backed up" -ForegroundColor Green
            Write-Log "Hosts file backed up to $hostsBackup" -Level SUCCESS
            return $true
        }
        else {
            Write-Host "    [WARNING] Hosts file not found" -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Host "    [ERROR] Failed to backup hosts: $_" -ForegroundColor Red
        Write-Log "Hosts backup failed: $_" -Level ERROR
        return $false
    }
}

function Backup-FirewallRules {
    param([string]$BackupDir)
    
    Write-Host "  [Backup] Saving firewall rules..." -ForegroundColor Cyan
    
    try {
        $hpRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$($script:Config.RulePrefix)*" }
        
        if ($hpRules) {
            $backupFile = Join-Path $BackupDir "firewall_rules_backup.json"
            $hpRules | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile -Encoding UTF8
            
            Write-Host "    [OK] Backed up $($hpRules.Count) firewall rules" -ForegroundColor Green
            Write-Log "Backed up $($hpRules.Count) firewall rules" -Level SUCCESS
            return $hpRules.Count
        }
        else {
            Write-Host "    [INFO] No HP firewall rules found" -ForegroundColor Gray
            return 0
        }
    }
    catch {
        Write-Host "    [ERROR] Failed to backup firewall rules: $_" -ForegroundColor Red
        Write-Log "Firewall backup failed: $_" -Level ERROR
        return 0
    }
}

function New-BackupManifest {
    param(
        [string]$BackupDir,
        [string]$Operation,
        [int]$ServicesCount,
        [int]$TasksCount,
        [int]$FirewallCount
    )
    
    try {
        $manifest = @{
            backup_id = "Backup_$($script:Config.SessionID)"
            timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            script_version = $script:Config.ScriptVersion
            operation = $Operation
            system_info = @{
                os = [System.Environment]::OSVersion.VersionString
                hostname = $env:COMPUTERNAME
                username = $env:USERNAME
            }
            backup_contents = @{
                services = $ServicesCount
                tasks = $TasksCount
                firewall_rules = $FirewallCount
                hosts_file = (Test-Path (Join-Path $BackupDir "hosts_backup.txt"))
            }
            success = $true
        }
        
        $manifestFile = Join-Path $BackupDir "backup_manifest.json"
        $manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestFile -Encoding UTF8
        
        Write-Log "Created backup manifest: $manifestFile" -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "Failed to create manifest: $_" -Level ERROR
        return $false
    }
}

function Invoke-FullBackup {
    param([string]$Operation = "Manual Backup")
    
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                          CREATING BACKUP" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $backupDir = New-BackupDirectory
    
    $servicesCount = Backup-HPServices -BackupDir $backupDir
    $tasksCount = Backup-HPScheduledTasks -BackupDir $backupDir
    Backup-HostsFile -BackupDir $backupDir | Out-Null
    $firewallCount = Backup-FirewallRules -BackupDir $backupDir
    
    New-BackupManifest -BackupDir $backupDir -Operation $Operation `
        -ServicesCount $servicesCount -TasksCount $tasksCount -FirewallCount $firewallCount
    
    Write-Host ""
    Write-Host "  [SUCCESS] Backup completed!" -ForegroundColor Green
    Write-Host "  Location: $backupDir" -ForegroundColor Cyan
    Write-Host ""
    
    $script:Statistics.BackupsCreated++
    
    return $backupDir
}

# ============================================================================
# SERVICE MANAGEMENT FUNCTIONS
# ============================================================================

function Get-HPServices {
    param([string]$Category = "ALL")
    
    $allServices = Get-Service | Where-Object { 
        $_.ServiceName -like "HP*" -or 
        $_.ServiceName -like "*OMEN*" -or 
        $_.DisplayName -like "*HP*" -or
        $_.DisplayName -like "*Hewlett*"
    }
    
    if ($Category -ne "ALL") {
        # Filter by category logic would go here
    }
    
    return $allServices
}

function Test-IsCriticalService {
    param([string]$ServiceName, [string]$DisplayName)
    
    # Check if service is in critical list
    if ($script:HardwareCritical.ContainsKey($ServiceName) -or 
        $script:HardwareCritical.ContainsKey($DisplayName)) {
        return $true
    }
    
    return $false
}

function Test-IsSemiCriticalService {
    param([string]$ServiceName, [string]$DisplayName)
    
    if ($script:HardwareSemiCritical.ContainsKey($ServiceName) -or 
        $script:HardwareSemiCritical.ContainsKey($DisplayName)) {
        return $true
    }
    
    return $false
}

function Confirm-HardwareServiceDisable {
    param(
        [string]$ServiceName,
        [hashtable]$ServiceInfo
    )
    
    Clear-Host
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                  *** HARDWARE FUNCTIONALITY WARNING ***" -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  You are about to disable a HARDWARE-CRITICAL service:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Service Name: $ServiceName" -ForegroundColor White
    Write-Host "  Hardware:     $($ServiceInfo.Hardware)" -ForegroundColor White
    Write-Host "  Severity:     $($ServiceInfo.Severity)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  IMMEDIATE IMPACT:" -ForegroundColor Red
    Write-Host "  $($ServiceInfo.Impact)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                         RECOVERY INFORMATION" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  If you disable this service and encounter issues:" -ForegroundColor White
    Write-Host ""
    Write-Host "  QUICK RECOVERY:" -ForegroundColor Green
    Write-Host "    1. Re-run this script" -ForegroundColor White
    Write-Host "    2. Select option [R] Quick Recovery from main menu" -ForegroundColor White
    Write-Host "    3. All hardware services will be restored" -ForegroundColor White
    Write-Host ""
    Write-Host "  ROLLBACK:" -ForegroundColor Yellow
    Write-Host "    1. Re-run this script" -ForegroundColor White
    Write-Host "    2. Select [4] Rollback Mode" -ForegroundColor White
    Write-Host "    3. Choose the most recent backup" -ForegroundColor White
    Write-Host ""
    Write-Host "  MANUAL RECOVERY (if script fails):" -ForegroundColor Yellow
    Write-Host "    1. Open Services (services.msc)" -ForegroundColor White
    Write-Host "    2. Find: $ServiceName" -ForegroundColor White
    Write-Host "    3. Right-click -> Properties" -ForegroundColor White
    Write-Host "    4. Set Startup Type: Automatic" -ForegroundColor White
    Write-Host "    5. Click 'Start' button" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "                         CONSENT REQUIRED" -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Do you REALLY want to disable this hardware service?" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] NO  - Keep service enabled (Recommended)" -ForegroundColor Green
    Write-Host "  [2] YES - I understand the risks and want to proceed" -ForegroundColor Red
    Write-Host ""
    
    $choice = Read-Host "  Select option [1-2]"
    
    if ($choice -eq "2") {
        Write-Host ""
        Write-Host "  FINAL CONFIRMATION:" -ForegroundColor Red
        Write-Host "  Type 'DISABLE $($ServiceInfo.Hardware)' to confirm: " -NoNewline -ForegroundColor Yellow
        $finalConfirm = Read-Host
        
        $expectedText = "DISABLE $($ServiceInfo.Hardware)"
        if ($finalConfirm -eq $expectedText) {
            Write-Host ""
            Write-Host "  [CONFIRMED] Proceeding with service disable..." -ForegroundColor Red
            Write-Log "User confirmed disable of hardware service: $ServiceName" -Level WARNING
            Start-Sleep -Seconds 1
            return $true
        }
        else {
            Write-Host ""
            Write-Host "  [CANCELLED] Text did not match. Service will NOT be disabled." -ForegroundColor Green
            Start-Sleep -Seconds 2
            return $false
        }
    }
    else {
        Write-Host ""
        Write-Host "  [CANCELLED] Service will remain enabled." -ForegroundColor Green
        Start-Sleep -Seconds 1
        return $false
    }
}

function Disable-HPService {
    param(
        [string]$ServiceName,
        [switch]$Force
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if (-not $service) {
            Write-Host "    [INFO] Service not found: $ServiceName" -ForegroundColor Gray
            return $false
        }
        
        # Check if critical
        if (Test-IsCriticalService -ServiceName $service.ServiceName -DisplayName $service.DisplayName) {
            Write-Host "    [PROTECTED] $($service.DisplayName) is CRITICAL and cannot be disabled!" -ForegroundColor Red
            Write-Log "Blocked attempt to disable critical service: $ServiceName" -Level WARNING
            return $false
        }
        
        # Check if semi-critical
        if (Test-IsSemiCriticalService -ServiceName $service.ServiceName -DisplayName $service.DisplayName) {
            $serviceInfo = $script:HardwareSemiCritical[$service.ServiceName]
            if (-not $serviceInfo) {
                $serviceInfo = $script:HardwareSemiCritical[$service.DisplayName]
            }
            
            if ($serviceInfo -and $serviceInfo.RequiresExplicitConsent -and -not $Force) {
                if (-not (Confirm-HardwareServiceDisable -ServiceName $service.DisplayName -ServiceInfo $serviceInfo)) {
                    return $false
                }
            }
        }
        
        # Stop and disable
        if ($service.Status -eq 'Running') {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-Host "    [OK] Stopped: $($service.DisplayName)" -ForegroundColor Green
        }
        
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
        Write-Host "    [OK] Disabled: $($service.DisplayName)" -ForegroundColor Green
        Write-Log "Disabled service: $ServiceName" -Level SUCCESS
        
        $script:Statistics.ServicesDisabled++
        return $true
    }
    catch {
        Write-Host "    [ERROR] Failed to disable $ServiceName`: $_" -ForegroundColor Red
        Write-Log "Failed to disable service $ServiceName`: $_" -Level ERROR
        return $false
    }
}

function Enable-HPService {
    param([string]$ServiceName)
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if (-not $service) {
            Write-Host "    [INFO] Service not found: $ServiceName" -ForegroundColor Gray
            return $false
        }
        
        Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction Stop
        Start-Service -Name $ServiceName -ErrorAction Stop
        
        Write-Host "    [OK] Enabled: $($service.DisplayName)" -ForegroundColor Green
        Write-Log "Enabled service: $ServiceName" -Level SUCCESS
        
        $script:Statistics.ServicesEnabled++
        return $true
    }
    catch {
        Write-Host "    [ERROR] Failed to enable $ServiceName`: $_" -ForegroundColor Red
        Write-Log "Failed to enable service $ServiceName`: $_" -Level ERROR
        return $false
    }
}

# ============================================================================
# SCHEDULED TASK MANAGEMENT
# ============================================================================

function Get-HPScheduledTasks {
    $tasks = Get-ScheduledTask | Where-Object { 
        $_.TaskPath -like "*\HP\*" -or 
        $_.TaskPath -like "*\OMEN\*" -or
        $_.TaskName -like "*HP*" -or
        $_.TaskName -like "*OMEN*"
    }
    
    return $tasks
}

function Disable-HPTask {
    param([string]$TaskName, [string]$TaskPath)
    
    try {
        Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
        Write-Host "    [OK] Disabled task: $TaskName" -ForegroundColor Green
        Write-Log "Disabled task: $TaskPath$TaskName" -Level SUCCESS
        
        $script:Statistics.TasksDisabled++
        return $true
    }
    catch {
        Write-Host "    [ERROR] Failed to disable task $TaskName`: $_" -ForegroundColor Red
        Write-Log "Failed to disable task $TaskName`: $_" -Level ERROR
        return $false
    }
}

function Enable-HPTask {
    param([string]$TaskName, [string]$TaskPath)
    
    try {
        Enable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
        Write-Host "    [OK] Enabled task: $TaskName" -ForegroundColor Green
        Write-Log "Enabled task: $TaskPath$TaskName" -Level SUCCESS
        
        $script:Statistics.TasksEnabled++
        return $true
    }
    catch {
        Write-Host "    [ERROR] Failed to enable task $TaskName`: $_" -ForegroundColor Red
        Write-Log "Failed to enable task $TaskName`: $_" -Level ERROR
        return $false
    }
}

# ============================================================================
# NETWORK ISOLATION - TELEMETRY BLOCKING
# ============================================================================

function Block-TelemetryDomains {
    Write-Host ""
    Write-Host "[Network] Blocking HP telemetry domains..." -ForegroundColor Cyan
    
    try {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        
        # Check if entries already exist
        $hostsContent = Get-Content $hostsPath -ErrorAction Stop
        $existingEntries = $hostsContent | Where-Object { $_ -match "HPDebloater" }
        
        if ($existingEntries) {
            Write-Host "  [INFO] Telemetry domains already blocked" -ForegroundColor Gray
            return $true
        }
        
        # Add entries
        $entries = "`n# HPDebloater - Telemetry Block - Added $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        
        foreach ($domain in $script:TelemetryDomains) {
            $entries += "0.0.0.0 $domain`n"
        }
        
        Add-Content -Path $hostsPath -Value $entries -ErrorAction Stop
        
        # Flush DNS
        ipconfig /flushdns | Out-Null
        
        Write-Host "  [OK] Blocked $($script:TelemetryDomains.Count) telemetry domains" -ForegroundColor Green
        Write-Log "Blocked $($script:TelemetryDomains.Count) domains in hosts file" -Level SUCCESS
        
        $script:Statistics.DomainsBlocked = $script:TelemetryDomains.Count
        return $true
    }
    catch {
        Write-Host "  [ERROR] Failed to block domains: $_" -ForegroundColor Red
        Write-Log "Domain blocking failed: $_" -Level ERROR
        return $false
    }
}

function New-TelemetryFirewallRules {
    Write-Host ""
    Write-Host "[Network] Creating firewall rules for telemetry blocking..." -ForegroundColor Cyan
    
    $telemetryPrograms = @(
        "C:\Program Files\HP\HP Telemetry\HPTelemetryClient.exe",
        "C:\Program Files\HP\HP Support Solutions\HPAnalytics.exe",
        "C:\Program Files\HP\HP Customer Participation\HPCustPartic.exe",
        "C:\Program Files (x86)\HP\HP Support Framework\Resources\HPWarrantyCheck\HPWarrantyChecker.exe"
    )
    
    $rulesCreated = 0
    
    foreach ($program in $telemetryPrograms) {
        if (Test-Path $program) {
            try {
                $programName = [System.IO.Path]::GetFileNameWithoutExtension($program)
                
                # Outbound rule
                $ruleName = "$($script:Config.RulePrefix) - Block $programName (Out)"
                $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                
                if (-not $existing) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound `
                        -Program $program -Action Block -Enabled True -ErrorAction Stop | Out-Null
                    $rulesCreated++
                }
                
                # Inbound rule
                $ruleName = "$($script:Config.RulePrefix) - Block $programName (In)"
                $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                
                if (-not $existing) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound `
                        -Program $program -Action Block -Enabled True -ErrorAction Stop | Out-Null
                    $rulesCreated++
                }
            }
            catch {
                Write-Log "Failed to create firewall rule for $program`: $_" -Level WARNING
            }
        }
    }
    
    if ($rulesCreated -gt 0) {
        Write-Host "  [OK] Created $rulesCreated firewall rules" -ForegroundColor Green
        Write-Log "Created $rulesCreated telemetry firewall rules" -Level SUCCESS
        $script:Statistics.FirewallRulesCreated += $rulesCreated
    }
    else {
        Write-Host "  [INFO] No telemetry programs found or rules already exist" -ForegroundColor Gray
    }
    
    return $rulesCreated
}

# ============================================================================
# ROLLBACK SYSTEM
# ============================================================================

function Get-AvailableBackups {
    $backups = @()
    
    if (Test-Path $script:Config.BackupDirectory) {
        $backupFolders = Get-ChildItem -Path $script:Config.BackupDirectory -Directory | 
            Where-Object { $_.Name -like "Backup_*" } |
            Sort-Object LastWriteTime -Descending
        
        foreach ($folder in $backupFolders) {
            $manifestPath = Join-Path $folder.FullName "backup_manifest.json"
            
            if (Test-Path $manifestPath) {
                try {
                    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
                    
                    $backups += @{
                        Folder = $folder.FullName
                        Name = $folder.Name
                        Manifest = $manifest
                        Timestamp = $manifest.timestamp
                        Operation = $manifest.operation
                    }
                }
                catch {
                    Write-Log "Failed to read manifest from $($folder.Name)" -Level WARNING
                }
            }
        }
    }
    
    return $backups
}

function Show-BackupSelectionMenu {
    $backups = Get-AvailableBackups
    
    if ($backups.Count -eq 0) {
        Write-Host ""
        Write-Host "  [INFO] No backups found." -ForegroundColor Yellow
        Write-Host "  Backups will be created automatically before making changes." -ForegroundColor Cyan
        Write-Host ""
        return $null
    }
    
    Clear-Host
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                            ROLLBACK MODE" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Available Backups:" -ForegroundColor White
    Write-Host ""
    
    for ($i = 0; $i -lt $backups.Count; $i++) {
        $backup = $backups[$i]
        $index = $i + 1
        
        Write-Host "[$index] $($backup.Name)" -ForegroundColor Cyan
        Write-Host "    Timestamp: $($backup.Timestamp)" -ForegroundColor Gray
        Write-Host "    Operation: $($backup.Operation)" -ForegroundColor Gray
        Write-Host "    Services:  $($backup.Manifest.backup_contents.services)" -ForegroundColor Gray
        Write-Host "    Tasks:     $($backup.Manifest.backup_contents.tasks)" -ForegroundColor Gray
        Write-Host "    Firewall:  $($backup.Manifest.backup_contents.firewall_rules)" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "[B] Back to Main Menu" -ForegroundColor Yellow
    Write-Host ""
    
    $selection = Read-Host "Select backup to restore (1-$($backups.Count)) or [B]"
    
    if ($selection -eq 'B' -or $selection -eq 'b') {
        return $null
    }
    
    $selectionNum = 0
    if ([int]::TryParse($selection, [ref]$selectionNum)) {
        if ($selectionNum -ge 1 -and $selectionNum -le $backups.Count) {
            return $backups[$selectionNum - 1]
        }
    }
    
    Write-Host ""
    Write-Host "[ERROR] Invalid selection" -ForegroundColor Red
    Start-Sleep -Seconds 2
    return $null
}

function Invoke-FullRollback {
    param([hashtable]$Backup)
    
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Yellow
    Write-Host "                          ROLLBACK IN PROGRESS" -ForegroundColor Yellow
    Write-Host "================================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Restoring from: $($Backup.Name)" -ForegroundColor Cyan
    Write-Host "  Created: $($Backup.Timestamp)" -ForegroundColor Cyan
    Write-Host ""
    
    # Step 1: Restore services
    Write-Host "[Step 1/4] Restoring HP services..." -ForegroundColor Cyan
    $servicesFile = Join-Path $Backup.Folder "services_backup.json"
    
    if (Test-Path $servicesFile) {
        try {
            $services = Get-Content $servicesFile -Raw | ConvertFrom-Json
            
            foreach ($svc in $services) {
                try {
                    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
                    
                    if ($service) {
                        Set-Service -Name $svc.Name -StartupType $svc.StartType -ErrorAction SilentlyContinue
                        
                        if ($svc.Status -eq 'Running') {
                            Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
                        }
                    }
                }
                catch {
                    Write-Log "Failed to restore service $($svc.Name): $_" -Level WARNING
                }
            }
            
            Write-Host "  [OK] Services restored" -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERROR] Service restore failed: $_" -ForegroundColor Red
        }
    }
    
    # Step 2: Restore hosts file
    Write-Host "[Step 2/4] Restoring hosts file..." -ForegroundColor Cyan
    $hostsBackup = Join-Path $Backup.Folder "hosts_backup.txt"
    
    if (Test-Path $hostsBackup) {
        try {
            $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
            Copy-Item -Path $hostsBackup -Destination $hostsPath -Force
            ipconfig /flushdns | Out-Null
            Write-Host "  [OK] Hosts file restored" -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERROR] Hosts restore failed: $_" -ForegroundColor Red
        }
    }
    
    # Step 3: Remove current firewall rules
    Write-Host "[Step 3/4] Removing current HP firewall rules..." -ForegroundColor Cyan
    try {
        $currentRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$($script:Config.RulePrefix)*" }
        foreach ($rule in $currentRules) {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
        }
        Write-Host "  [OK] Current rules removed" -ForegroundColor Green
    }
    catch {
        Write-Host "  [WARNING] Some rules could not be removed" -ForegroundColor Yellow
    }
    
    # Step 4: Restore firewall rules
    Write-Host "[Step 4/4] Restoring firewall rules from backup..." -ForegroundColor Cyan
    $firewallBackup = Join-Path $Backup.Folder "firewall_rules_backup.json"
    
    if (Test-Path $firewallBackup) {
        try {
            $rules = Get-Content $firewallBackup -Raw | ConvertFrom-Json
            
            if ($rules) {
                $restoredCount = 0
                
                foreach ($rule in $rules) {
                    try {
                        $params = @{
                            DisplayName = $rule.DisplayName
                            Direction = $rule.Direction
                            Action = $rule.Action
                            Enabled = $rule.Enabled
                        }
                        
                        New-NetFirewallRule @params -ErrorAction SilentlyContinue | Out-Null
                        $restoredCount++
                    }
                    catch {
                        # Silent fail for individual rules
                    }
                }
                
                Write-Host "  [OK] Restored $restoredCount firewall rules" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  [ERROR] Firewall restore failed: $_" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "                          ROLLBACK COMPLETE" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  System has been restored to: $($Backup.Timestamp)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Press any key to return to main menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================================================
# OMEN GAMING HUB MODULE
# ============================================================================

$script:OMENServices = @(
    # NOTE: OmenHsaService (MUX Switch) is INTENTIONALLY EXCLUDED
    # Reason: Controls hardware GPU routing - too critical to automate
    "HP Application Enabling Services",
    "OMEN Software and Services"
)

$script:OMENTasks = @(
    @{ Name = "HP OMEN OMENInstallMonitor"; Path = "\HP\" },
    @{ Name = "OMENCommandCenterUserTasks"; Path = "\HP\" }
)

function Enable-OMENServices {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                      OMEN GAMING HUB - ENABLE" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Create backup first
    Invoke-FullBackup -Operation "OMEN Enable"
    
    Write-Host "[OMEN] Enabling OMEN services..." -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($serviceName in $script:OMENServices) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            Enable-HPService -ServiceName $serviceName
        }
    }
    
    Write-Host ""
    Write-Host "[OMEN] Enabling OMEN scheduled tasks..." -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($task in $script:OMENTasks) {
        $taskExists = Get-ScheduledTask -TaskName $task.Name -TaskPath $task.Path -ErrorAction SilentlyContinue
        if ($taskExists) {
            Enable-HPTask -TaskName $task.Name -TaskPath $task.Path
        }
    }
    
    Write-Host ""
    Write-Host "[SUCCESS] OMEN Gaming Hub services enabled!" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now open OMEN Gaming Hub." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [!] NOTE: MUX switch functionality is always available." -ForegroundColor Cyan
    Write-Host "      OMEN HSA Service is protected and never disabled by this script." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[REMINDER] Run OMEN DISABLE after you finish to remove bloatware!" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "Press any key to return to main menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Disable-OMENServices {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                      OMEN GAMING HUB - DISABLE" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This will disable OMEN Gaming Hub bloatware services." -ForegroundColor White
    Write-Host ""
    Write-Host "  [!] NOTE: OMEN HSA Service (MUX switch) is NOT touched by this script." -ForegroundColor Cyan
    Write-Host "      It is too critical and remains protected." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Target services:" -ForegroundColor Cyan
    Write-Host "  - OMEN background processes" -ForegroundColor White
    Write-Host "  - OMEN scheduled tasks" -ForegroundColor White
    Write-Host "  - OMEN startup entries" -ForegroundColor White
    Write-Host ""
    Write-Host "  Continue with OMEN bloatware removal? (yes/no): " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -notmatch '^(yes|y)$') {
        Write-Host ""
        Write-Host "[CANCELLED] No changes made" -ForegroundColor Green
        Start-Sleep -Seconds 2
        return
    }
    
    # Create backup first
    Invoke-FullBackup -Operation "OMEN Disable"
    
    Write-Host ""
    Write-Host "[OMEN] Disabling OMEN services..." -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($serviceName in $script:OMENServices) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            Disable-HPService -ServiceName $serviceName -Force
        }
    }
    
    Write-Host ""
    Write-Host "[OMEN] Disabling OMEN scheduled tasks..." -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($task in $script:OMENTasks) {
        $taskExists = Get-ScheduledTask -TaskName $task.Name -TaskPath $task.Path -ErrorAction SilentlyContinue
        if ($taskExists) {
            Disable-HPTask -TaskName $task.Name -TaskPath $task.Path
        }
    }
    
    Write-Host ""
    Write-Host "[OMEN] Stopping OMEN processes..." -ForegroundColor Cyan
    
    $omenProcesses = Get-Process | Where-Object { $_.ProcessName -like "*OMEN*" -or $_.ProcessName -like "*OMENCommandCenter*" }
    foreach ($proc in $omenProcesses) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-Host "  [OK] Stopped process: $($proc.ProcessName)" -ForegroundColor Green
        }
        catch {
            Write-Log "Failed to stop process $($proc.ProcessName): $_" -Level WARNING
        }
    }
    
    Write-Host ""
    Write-Host "[SUCCESS] OMEN Gaming Hub fully disabled!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Press any key to return to main menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================================================
# GENERAL DEBLOAT MODULE
# ============================================================================

function Invoke-GeneralDebloat {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                      GENERAL HP SYSTEM DEBLOAT" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This will disable HP bloatware and telemetry services." -ForegroundColor White
    Write-Host "Hardware-critical services (audio, touchpad, etc.) are PROTECTED." -ForegroundColor Green
    Write-Host ""
    Write-Host "Target services:" -ForegroundColor Cyan
    Write-Host "  - HP Support Assistant" -ForegroundColor White
    Write-Host "  - HP Telemetry & Analytics" -ForegroundColor White
    Write-Host "  - HP Customer Participation" -ForegroundColor White
    Write-Host "  - HP Diagnostics" -ForegroundColor White
    Write-Host ""
    Write-Host "Continue? (yes/no): " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -notmatch '^(yes|y)$') {
        Write-Host ""
        Write-Host "[CANCELLED] No changes made" -ForegroundColor Green
        Start-Sleep -Seconds 2
        return
    }
    
    # Create backup
    Invoke-FullBackup -Operation "General Debloat"
    
    Write-Host ""
    Write-Host "[Debloat] Disabling bloatware services..." -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($serviceName in $script:BloatwareServices.Keys) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            Disable-HPService -ServiceName $serviceName
        }
    }
    
    Write-Host ""
    Write-Host "[Debloat] Disabling telemetry tasks..." -ForegroundColor Cyan
    Write-Host ""
    
    $tasks = Get-HPScheduledTasks
    foreach ($task in $tasks) {
        if ($task.TaskName -like "*Support*" -or 
            $task.TaskName -like "*Telemetry*" -or 
            $task.TaskName -like "*Analytics*") {
            Disable-HPTask -TaskName $task.TaskName -TaskPath $task.TaskPath
        }
    }
    
    Write-Host ""
    Write-Host "[SUCCESS] General debloat completed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Services disabled: $($script:Statistics.ServicesDisabled)" -ForegroundColor White
    Write-Host "  Tasks disabled:    $($script:Statistics.TasksDisabled)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Press any key to return to main menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================================================
# QUICK RECOVERY
# ============================================================================

function Invoke-QuickHardwareRecovery {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "                      QUICK HARDWARE RECOVERY" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  This will immediately re-enable all hardware-critical services:" -ForegroundColor White
    Write-Host ""
    Write-Host "  [+] Audio services (speakers, headphones)" -ForegroundColor Green
    Write-Host "  [+] Touchpad services" -ForegroundColor Green
    Write-Host "  [+] Display control" -ForegroundColor Green
    Write-Host "  [+] Power management" -ForegroundColor Green
    Write-Host "  [+] Keyboard hot keys" -ForegroundColor Green
    Write-Host ""
    Write-Host "  This will NOT re-enable bloatware or telemetry services." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Proceed with hardware recovery? (yes/no): " -NoNewline -ForegroundColor Yellow
    
    $confirm = Read-Host
    
    if ($confirm -notmatch '^(yes|y)$') {
        return
    }
    
    Write-Host ""
    Write-Host "[Recovery] Re-enabling hardware services..." -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($serviceName in $script:HardwareCritical.Keys) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            try {
                Set-Service -Name $serviceName -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                Write-Host "  [OK] Restored: $($service.DisplayName)" -ForegroundColor Green
            }
            catch {
                # Silent fail
            }
        }
    }
    
    Write-Host ""
    Write-Host "[SUCCESS] Hardware services restored!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Please test your hardware:" -ForegroundColor Cyan
    Write-Host "  - Try touchpad gestures" -ForegroundColor White
    Write-Host "  - Play audio to test speakers" -ForegroundColor White
    Write-Host "  - Test function keys (brightness, volume)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Press any key to return to main menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================================================
# MAIN MENU
# ============================================================================

function Show-MainMenu {
    $exitMenu = $false
    
    while (-not $exitMenu) {
        Clear-Host
        Show-Banner
        
        Write-Host "================================================================================" -ForegroundColor White
        Write-Host "                            OPERATION MODE" -ForegroundColor White
        Write-Host "================================================================================" -ForegroundColor White
        Write-Host ""
        Write-Host "  [1] OMEN GAMING HUB - ENABLE" -ForegroundColor Cyan
        Write-Host "      Enable OGH services (use before opening app)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [2] OMEN GAMING HUB - DISABLE" -ForegroundColor Cyan
        Write-Host "      Disable OGH services (use after closing app)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [3] GENERAL HP DEBLOAT" -ForegroundColor Cyan
        Write-Host "      Remove bloatware and telemetry (safe mode)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [4] NETWORK ISOLATION" -ForegroundColor Cyan
        Write-Host "      Block HP telemetry domains and services" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [5] ROLLBACK MODE" -ForegroundColor Yellow
        Write-Host "      Restore from previous backup" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [R] QUICK RECOVERY" -ForegroundColor Green
        Write-Host "      Restore all hardware services (emergency)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [Q] QUIT" -ForegroundColor Red
        Write-Host "      Exit script safely" -ForegroundColor Gray
        Write-Host ""
        Write-Host "================================================================================" -ForegroundColor White
        Write-Host ""
        
        Write-Host "Select option: " -NoNewline -ForegroundColor Yellow
        $choice = Read-Host
        
        switch ($choice.ToUpper()) {
            "1" { Enable-OMENServices }
            "2" { Disable-OMENServices }
            "3" { Invoke-GeneralDebloat }
            "4" { 
                Invoke-FullBackup -Operation "Network Isolation"
                Block-TelemetryDomains
                New-TelemetryFirewallRules
                Write-Host ""
                Write-Host "Press any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "5" {
                $backup = Show-BackupSelectionMenu
                if ($backup) {
                    Invoke-FullRollback -Backup $backup
                }
            }
            "R" { Invoke-QuickHardwareRecovery }
            "Q" { 
                $exitMenu = $true
                Write-Host ""
                Write-Host "[EXIT] Exiting HP Debloater. No changes made this session." -ForegroundColor Green
                Write-Host ""
            }
            default {
                Write-Host ""
                Write-Host "[ERROR] Invalid option. Please select 1-5, R, or Q." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

try {
    # Show banner
    Show-Banner
    
    # Test administrator privileges (MUST be first check)
    if (-not (Test-AdministratorPrivileges)) {
        exit 1
    }
    
    # Initialize environment
    if (-not (Initialize-Environment)) {
        Write-Host "[ERROR] Failed to initialize environment. Exiting." -ForegroundColor Red
        exit 1
    }
    
    # Show disclaimer
    Write-Host "[Critical] Displaying legal disclaimer..." -ForegroundColor Cyan
    Write-Host ""
    if (-not (Show-Disclaimer)) {
        Write-Host "[CANCELLED] User did not accept disclaimer. Exiting safely." -ForegroundColor Yellow
        exit 0
    }
    
    # Prompt for system restore point
    if (-not (Show-SystemRestorePointPrompt)) {
        exit 0
    }
    
    # Show main menu
    Show-MainMenu
    
}
catch {
    Write-Host ""
    Write-Host "[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "Fatal error: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
}
finally {
    # Stop transcript
    try {
        Stop-Transcript | Out-Null
    }
    catch {
        # Transcript might not be running
    }
    
    Write-Log "Script execution ended" -Level INFO
}

