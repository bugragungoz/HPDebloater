# HP Debloater

<div align="center">

⚠️ **CRITICAL WARNING - UNTESTED SOFTWARE** ⚠️

**THIS SCRIPT IS EXPERIMENTAL AND POTENTIALLY DANGEROUS**

May cause system instability, hardware malfunction, or warranty void.  
**Use at your own risk. Author assumes NO responsibility.**

</div>

---

PowerShell script for removing HP bloatware and blocking telemetry on HP laptops while protecting critical hardware functionality.

## Overview

Hardware-aware debloater that safely removes HP bloatware (Support Assistant, telemetry, analytics) while protecting essential laptop hardware services (audio, touchpad, display, power management, keyboard).

## Critical Exclusions

This script **INTENTIONALLY DOES NOT TOUCH**:
- ❌ BIOS/UEFI configuration services (can brick system)
- ❌ MUX switch / GPU multiplexer services (hardware routing)
- ❌ Firmware update services (security critical)
- ❌ TPM/Security chip services (system lockout risk)
- ❌ Hardware management engines (Intel ME, AMD PSP)

## Protected Hardware Services

**NEVER Disabled** (Essential Functionality):
- 🔒 Audio services (speakers, headphones)
- 🔒 Touchpad services (trackpad control)
- 🔒 Display control (brightness adjustment)
- 🔒 Power management (battery optimization)
- 🔒 WMI service (hardware communication)
- 🔒 Hotkey service (function keys)
- 🔒 Wireless button (WiFi/Bluetooth toggle)

## Features

- **Safe Bloatware Removal**: Targets only non-essential HP software
- **Network Isolation**: Blocks 21 HP telemetry domains (hosts + firewall)
- **Hardware Protection**: Critical services cannot be disabled
- **Comprehensive Backup**: Services, tasks, firewall rules, hosts file
- **Full Rollback**: Complete system state restoration
- **Multi-Stage Consent**: 5-page disclaimer + explicit confirmations
- **OMEN Support**: Enable/disable OMEN Gaming Hub (MUX protected)

## Target Services

### Bloatware (Safe to Remove)
- HP Support Assistant
- HP Telemetry & Analytics
- HP Customer Participation Program
- HP Diagnostics
- HP JumpStart Bridge
- HP Documentation

### Network Blocking
- `telemetry.hp.com`, `metrics.hp.com`, `analytics.hp.com`
- `tracking.hp.com`, `ceip.hp.com`, `feedback.hp.com`
- HP crash reporting and diagnostics domains
- OMEN-specific telemetry domains

## Usage

### Prerequisites
- **Administrator privileges required**
- **Windows 10/11**
- **HP Laptop** (optimized for OMEN series)
- **Create System Restore Point** (mandatory recommendation)

### Installation

1. **Open PowerShell as Administrator**

2. **Navigate to script directory**
   ```powershell
   cd C:\path\to\HPDebloater
   ```

3. **Set execution policy** (current session only)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
   ```

4. **Run the script**
   ```powershell
   .\HPDebloater.ps1
   ```

### Operation Modes

```
[1] OMEN GAMING HUB - ENABLE
    Enable OMEN services temporarily (for settings access)

[2] OMEN GAMING HUB - DISABLE
    Disable OMEN bloatware (MUX switch remains protected)

[3] GENERAL HP DEBLOAT
    Remove HP bloatware and telemetry (safe mode)

[4] NETWORK ISOLATION
    Block HP telemetry domains and analytics services

[5] ROLLBACK MODE
    Restore system from backup

[R] QUICK RECOVERY
    Emergency restore of all hardware services

[Q] QUIT
```

## Safety Mechanisms

### 1. Multi-Layer Protection
- Critical service whitelist (auto-blocked from disable)
- Semi-critical warnings (two-stage consent required)
- Explicit consent phrases for dangerous operations

### 2. Backup System
```
HPDebloater_Backups/
└── Backup_YYYYMMDD_HHMMSS/
    ├── backup_manifest.json        # Metadata
    ├── services_backup.json        # Service states
    ├── task_*.xml                  # Scheduled tasks (XML export)
    ├── hosts_backup.txt            # Hosts file
    └── firewall_rules_backup.json  # Firewall rules
```

### 3. Disclaimer System
- 5-page comprehensive disclaimer
- Warranty void warnings
- Hardware impact explanations
- Required consent: `"I HAVE READ ALL 5 PAGES AND ACCEPT ALL RISKS"`

### 4. Recovery Options
- **Quick Recovery**: One-click hardware service restoration
- **Full Rollback**: Complete system state restore from backup
- **Manual Recovery**: Step-by-step instructions provided
- **System Restore Point**: Windows-native recovery (user-created)

## Technical Details

### Blocking Methodology

1. **Service Management**: Disable bloatware services via `Set-Service`
2. **Scheduled Tasks**: Disable HP tasks via `Disable-ScheduledTask`
3. **Hosts File**: Redirect telemetry domains to `0.0.0.0`
4. **Firewall Rules**: Program-based blocking (inbound + outbound)

### File Locations

- Logs: `HPDebloater_Logs\HPDebloater_YYYYMMDD_HHMMSS.log`
- Backups: `HPDebloater_Backups\Backup_YYYYMMDD_HHMMSS\`
- Transcript: `HPDebloater_Logs\HPDebloater_Transcript_YYYYMMDD_HHMMSS.log`

## Warnings

### ⚠️ WARRANTY IMPLICATIONS
- **HP warranty MAY BE VOIDED** by modifying system services
- HP Support may refuse assistance on modified systems
- HP may flag system as "modified" and deny service

### ⚠️ HARDWARE RISKS
If you accidentally disable wrong services:
- Touchpad may stop working (external mouse required)
- Speakers/headphones may produce no sound
- Brightness control may fail
- Battery optimization may be lost
- Function keys (Fn) may not work

### ⚠️ SYSTEM STABILITY
- Always create Windows System Restore Point first
- Test in non-production environment if possible
- Understand implications before proceeding
- Keep external mouse/keyboard available

## Recovery Procedures

### Quick Hardware Recovery (If Hardware Stops Working)
1. Re-run script as Administrator
2. Select option `[R] QUICK RECOVERY`
3. All hardware services will be restored immediately

### Full Rollback (Complete Restoration)
1. Re-run script as Administrator
2. Select option `[5] ROLLBACK MODE`
3. Choose backup to restore
4. System will be restored to previous state

### Manual Recovery (If Script Fails)
1. Open Services (`services.msc`)
2. Find affected HP service
3. Set Startup Type: `Automatic`
4. Click `Start` button

### System Restore (Last Resort)
1. Press `Windows + R`
2. Type: `rstrui.exe`
3. Follow wizard to restore to point created before script

## System Requirements

- **OS**: Windows 10 (1809+) or Windows 11
- **Hardware**: HP Laptop (Desktop untested)
- **Privileges**: Administrator rights
- **PowerShell**: 5.1 or higher
- **Disk Space**: ~50MB for backups

## Tested Configurations

⚠️ **NONE - THIS SCRIPT IS UNTESTED**

Please report issues and test results via GitHub Issues.

## Legal Disclaimer

```
THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
THE AUTHOR ACCEPTS NO LIABILITY FOR ANY DAMAGES, WARRANTY VOIDS,
SYSTEM FAILURES, DATA LOSS, OR HARDWARE DAMAGE.

YOU ARE SOLELY RESPONSIBLE FOR:
- Compliance with HP Terms of Service
- System integrity and functionality  
- Warranty implications
- All consequences of using this script

BY USING THIS SCRIPT, YOU ACKNOWLEDGE FULL RESPONSIBILITY.
```

## Credits

- **Author**: Bugra
- **Concept & Design**: Bugra
- **Development**: Claude 4.5 Sonnet AI

## License

MIT License - Use at your own risk


---

<div align="center">

**Always create a System Restore Point before running!**


</div>

