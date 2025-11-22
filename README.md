# HP Telemetry & Ad Blocker

PowerShell script for disabling HP telemetry and advertisement services on HP laptops.

**OMEN Gaming Hub Safe**: Does not affect gaming features, fan control, temperature monitoring, or graphics switching.

## Overview

Lightweight script that disables HP data collection and advertisement services only. OMEN Gaming Hub, hardware controls, and gaming features remain fully functional.

## Protected Services

This script does NOT touch:
- OMEN Gaming Hub
- Fan control
- Temperature monitoring
- Graphics switching
- Performance controls
- Audio services
- Touchpad services
- Display control
- Power management
- Keyboard functions

## Target Services

Script blocks only telemetry and advertisements:
- HP Touchpoint Analytics
- HP Customer Participation Program
- HP Support Solutions Framework (ads/promotions)
- HP JumpStart promotional launcher

## Features

- **OMEN-Safe**: ZERO impact on gaming features
- **Telemetry Blocking**: Disables HP data collection services
- **Ad Blocking**: Removes HP promotional services
- **Network Isolation**: Blocks 21+ HP telemetry domains (hosts + firewall)
- **Automatic Backup**: Full rollback capability included
- **Simple Interface**: 2-page disclaimer, easy to use
- **Hardware Friendly**: All hardware features remain operational

## Target Services (ONLY 4 Services)

### Telemetry Services
- **HP Touchpoint Analytics** (data collection)
- **HP Customer Participation Program** (feedback/tracking)

### Advertisement Services
- **HP Support Solutions Framework** (promotional popups)
- **HP JumpStart Bridge** (promotional launcher)

### Network Blocking
- `telemetry.hp.com`, `metrics.hp.com`, `analytics.hp.com`
- `tracking.hp.com`, `ceip.hp.com`, `feedback.hp.com`
- HP crash reporting and diagnostics domains
- OMEN-specific telemetry domains

## Usage

### Prerequisites
- **Administrator privileges required**
- **Windows 10/11**
- **HP Laptop** (OMEN Gaming Hub will NOT be affected)
- **System Restore Point** (optional - automatic backup included)

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
[1] BLOCK TELEMETRY & ADS
    Disable HP telemetry and advertisement services
    (OMEN Gaming Hub fully protected and functional)

[2] ROLLBACK MODE
    Restore from previous backup (undo changes)

[Q] QUIT
    Exit script safely
```

## Safety Mechanisms

### 1. OMEN Gaming Hub Protection
- OMEN services are NEVER touched by this script
- Fan control, temperature monitoring fully operational
- Graphics switching and performance controls untouched
- All gaming features remain functional

### 2. Automatic Backup System
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
- 2-page simple disclaimer
- Clear explanation of what's blocked
- OMEN protection explicitly stated
- Required consent: `"I ACCEPT"`

### 4. Easy Rollback
- **Full Rollback**: Complete restoration from backup
- **Automatic Backup**: Created before any changes
- **One-Click Restore**: Simple menu option

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

## After Running This Script

Changes:
- HP will not collect usage data
- HP promotional popups disabled
- Telemetry domains blocked

Unchanged:
- All hardware features work normally
- OMEN Gaming Hub functions
- Fan control operational
- Temperature monitoring functional
- Graphics switching intact

Risks:
- Minimal - only telemetry services affected
- Easy rollback available
- Automatic backup created before changes

## Recovery Procedures

### Easy Rollback (Undo All Changes)
1. Re-run script as Administrator
2. Select option `[2] ROLLBACK MODE`
3. Choose backup to restore
4. All changes will be reversed

### Manual Re-enable (If Needed)
1. Open Services (`services.msc`)
2. Find HP telemetry service
3. Set Startup Type: `Automatic`
4. Click `Start` button

## System Requirements

- **OS**: Windows 10 (1809+) or Windows 11
- **Hardware**: HP Laptop (especially OMEN series)
- **Privileges**: Administrator rights
- **PowerShell**: 5.1 or higher
- **Disk Space**: ~10MB for backups

## Version History

Previous version (1.0.0) issues:
- Broke OMEN Gaming Hub features
- Disabled graphics switching controls
- Affected fan control and temperature monitoring
- Impacted performance management

Current version (2.0.0) improvements:
- Only targets telemetry and ads
- Leaves all gaming features intact
- Keeps hardware controls functional
- Simpler and safer to use

## Legal Disclaimer

```
THIS SOFTWARE IS PROVIDED "AS IS" FOR PERSONAL USE.
THE AUTHOR ACCEPTS NO LIABILITY FOR ANY CONSEQUENCES.

This script ONLY disables telemetry and advertisement services.
OMEN Gaming Hub and hardware features remain fully functional.

You have the right to disable telemetry on your own device.
Automatic backups allow easy restoration if needed.
```

## Contributing

Contributions welcome:
- Test on different HP OMEN models
- Report telemetry services we missed
- Suggest improvements for OMEN safety
- Share your results

## Credits

- **Author**: Bugra
- **Concept & Design**: Bugra
- **Development**: Claude 4.5 Sonnet AI
- **Version**: 2.0.0 (OMEN-Safe Edition)

## License

MIT License - Use at your own risk

## Support

Use GitHub Issues for bug reports and suggestions.

Reports from OMEN users confirming Gaming Hub functionality are appreciated.

---

**Note**: This script only blocks telemetry and ads. OMEN Gaming Hub, fan control, temperature monitoring, and graphics switching remain fully functional.

