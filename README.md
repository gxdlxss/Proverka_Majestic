# Majestic_Proverka

Windows console utility that performs a local system scan and saves a readable report to your Desktop.

⚠️ **Important (privacy & safety):** This project can collect a lot of information about a computer (process list, startup entries, USB history, file names, etc.).
Use it **only on your own PC** or on machines where you have **explicit permission**.

---

## Features

### Scan modes
- **Quick scan**: opens a set of URLs and the Windows **Recent** folder.
- **Full scan**: runs the full local analysis and generates a report.

### Full scan includes
- Basic user/computer info
- Last reboot time (SystemInfo + WMI)
- File Explorer “Recent” summary
- Windows install date/version/build (registry)
- Recycle Bin summary
- Event Logs “last write time”
- Recent Downloads summary
- Disk usage (PowerShell, fallback to wmic)
- USB storage history (USBSTOR registry)
- Connected USB hubs (WMI)
- Simple “DMA device” keyword check (PnP devices)
- Suspicious file search with **scoring** (filename patterns + random-name heuristics + size heuristics)

### Output
- Shows results in the console
- Saves the report to:

`%USERPROFILE%\Desktop\system_report.txt`

---

## Requirements

- **Windows** (uses `cmd`, `wevtutil`, PowerShell, registry, and some `wmic` calls)
- **Go** installed (recommended: Go 1.20+)

---

## Build

From the project folder:

```bat
go mod tidy
go build -o Majestic_Proverka.exe
```

---

## Run

```bat
Majestic_Proverka.exe
```

Follow the on-screen menu to choose **Quick** or **Full** scan.

---

## About network sending (Discord webhook)

The current code contains optional logic to send scan output via a Discord webhook.

✅ **Recommended:** keep the tool **local-only**.
If you plan to share this program or run it in any environment that isn't strictly your own machine, you should **remove** the webhook feature entirely (delete `sendToDiscord` / `sendDiscordMessage` and the webhook prompt) to avoid accidental data leakage.

---

## Suspicious file scoring (how it works)

The suspicious file search assigns a **score** based on:
- Filename keywords (e.g., “inject”, “loader”, “crack”, etc.)
- Random-looking names (character composition heuristics)
- Some size-based heuristics for executables/libraries

A higher score means “more suspicious by heuristics”.
This is **not antivirus** and may produce false positives.

---

## Troubleshooting

### “wmic is not recognized”
Some Windows builds remove/disable `wmic`. Options:
- Replace remaining `wmic` calls with PowerShell equivalents, or
- Run on a Windows build where `wmic` is available/enabled.

### Report file not saved
Make sure the Desktop folder exists and you have write permissions:
`%USERPROFILE%\Desktop`

---

## License

MIT (see `LICENSE`).
