# PC Inspector

A portable, dependency-free Windows hardware inspection utility written in
pure PowerShell. Designed for evaluating a PC before buying it second-hand —
think of it as a lightweight combination of CPU-Z, CrystalDiskInfo, HWiNFO
and Speccy in a single script.

## Highlights

- **Single portable script** — no installation, no registry modifications,
  no external dependencies.
- **Windows 10 / Windows 11**, PowerShell 5.1+ and PowerShell 7+.
- **No administrator rights required.** Privileged data (SMART wear,
  power-on hours, thermal zones) degrades gracefully to
  `Unknown (requires Administrator)` instead of failing.
- **Never crashes.** Every query is guarded with CIM → WMI → cmdlet →
  registry → COM fallbacks; unknown values are always reported as `Unknown`.
- Professional console UI with Unicode box drawing, colors and a progress
  indicator.
- **JSON and TXT export** of the complete report.
- Automated **health check** (warnings) and objective **buyer analysis**.
- Exit code `0` on success.

## Usage

```powershell
# Full inspection, console output only
.\PC-Inspector.ps1

# Inspection + JSON and TXT reports (written next to the script)
.\PC-Inspector.ps1 -Json -Txt

# GNU-style flags are accepted too
powershell -ExecutionPolicy Bypass -File .\PC-Inspector.ps1 --json --txt

# Custom export directory, no colors, ASCII borders
.\PC-Inspector.ps1 -Json -OutputPath D:\Reports -NoColor -Ascii
```

> Running as Administrator is optional but unlocks additional data:
> SSD wear level, power-on hours, disk temperatures and ACPI thermal zones.

### Parameters

| Parameter     | Alias      | Description                                   |
|---------------|------------|-----------------------------------------------|
| `-Json`       | `--json`   | Export the full report as JSON                |
| `-Txt`        | `--txt`    | Export the full report as plain text          |
| `-OutputPath` |            | Directory for export files (default: script folder) |
| `-NoColor`    | `--nocolor`| Disable colored output (`NO_COLOR` env var also honored) |
| `-Ascii`      | `--ascii`  | ASCII borders instead of Unicode box drawing  |

## What it inspects

| Section     | Details |
|-------------|---------|
| System      | Manufacturer, model, serial, SKU, Windows edition/build, install date, activation, uptime, Secure Boot, UEFI/Legacy, TPM, BitLocker, Windows 11 compatibility |
| CPU         | Model, generation (estimated), socket, cores/threads, clocks, L1/L2/L3 cache, virtualization/SLAT, AES-NI, AVX/AVX2/AVX-512, SSE versions, microcode revision |
| Motherboard | Vendor, model, serial, chipset (estimated), BIOS vendor/version/date, SMBIOS version |
| RAM         | Total, maximum supported, slots (total/used/free), channel configuration, and per module: vendor, part number, serial, capacity, speed, voltage, DDR generation, ECC, rank, form factor |
| Storage     | Per disk: model, firmware, serial, capacity, partition style, bus type, SSD/NVMe/HDD, RPM, drive letters, SMART status, estimated health, SSD life, power-on hours, temperature; volumes and TRIM |
| GPU         | Per GPU: vendor, model, VRAM (registry-accurate), driver version/date, integrated vs dedicated |
| Network     | Ethernet/Wi-Fi/Bluetooth, MAC, link speed, driver, IPv4/IPv6, gateway, DNS |
| USB         | Controllers, supported USB versions, connected devices |
| PCI         | Every PCI device with driver and status |
| Display     | Monitor model, manufacturer, year, diagonal size, active resolution and refresh rate |
| Battery     | Design vs full-charge capacity, wear level, cycle count, health estimate |
| Audio       | Devices with drivers |
| Sensors     | ACPI thermal zones, disk temperature, fans (where exposed) |

## Health check

Automatic warnings for: old BIOS, single-channel or slow RAM, missing SSD,
HDD boot drive, SMART problems, high temperatures, disabled virtualization,
low disk space, outdated GPU drivers, battery wear, inactive Windows
license, Legacy BIOS installs, and PCI devices with driver problems.

## Buyer analysis

Objective, factual observations to support a purchase decision — free RAM
slots, NVMe presence, boot-drive type, UEFI/TPM readiness for Windows 11,
BIOS age, battery capacity retention.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Inspection completed successfully |
| 1    | Fatal, unexpected failure |

## License

MIT
