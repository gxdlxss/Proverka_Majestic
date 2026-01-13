// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

var discordWebhook string

type DiscordMessage struct {
	Content string `json:"content"`
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║               SYSTEM SCANNER - STARTUP                   ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝\n")

	fmt.Println("Select scan mode:")
	fmt.Println("1. Quick scan (open URLs and Recent folder only)")
	fmt.Println("2. Full scan (complete system analysis)")
	fmt.Print("\nEnter choice (1 or 2): ")

	var choice int
	fmt.Scanln(&choice)

	if choice == 1 {
		fmt.Println("\n[QUICK SCAN MODE]")
		quickScan()
	} else if choice == 2 {
		fmt.Println("\n[FULL SCAN MODE]")
		fmt.Print("Enter Discord webhook URL (press Enter to skip): ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			discordWebhook = strings.TrimSpace(scanner.Text())
		}
		fullScan()
	} else {
		fmt.Println("Invalid choice. Exiting.")
		return
	}

	fmt.Print("\n\nPress Enter to exit...")
	fmt.Scanln()
}

func quickScan() {
	fmt.Println("\n[EXECUTING QUICK ACTIONS...]")
	executeQuickActions()
}

func fullScan() {
	fmt.Println("\n[1/3] EXECUTING DEFAULT ACTIONS...")
	executeBatchActionsWithProgress()

	fmt.Println("\n[2/3] COLLECTING SYSTEM INFORMATION...")
	systemInfo := collectSystemInfoWithProgress()

	fmt.Println("\n[3/3] SEARCHING FOR SUSPICIOUS FILES...")
	fileSearchResults := searchSuspiciousFilesWithProgress()

	clearConsole()
	showFinalReport(systemInfo, fileSearchResults)

	if discordWebhook != "" {
		fmt.Println("\n[SENDING RESULTS TO DISCORD...]")
		sendToDiscord(systemInfo, fileSearchResults)
	}
}

func executeQuickActions() {
	fmt.Println("  Opening password recovery URLs...")
	urls := []string{
		"https://0xcheats.net/auth/forgot/",
		"https://leet-cheats.ru/restore_password",
		"https://unicore.cloud/forum/lost-password/",
		"https://vanish-cheat.com/login",
	}
	for _, url := range urls {
		exec.Command("cmd", "/c", "start", "", url).Start()
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Println("  ✓ URLs opened")

	fmt.Println("  Opening additional URLs...")
	urls = []string{
		"https://oplata.info/info/",
		"https://funpay.com/account/login",
		"https://forum.majestic-rp.ru/",
		"https://discord.com/",
		"https://myactivity.google.com/myactivity?hl=ru&pli=1&q=cheat",
		"https://myactivity.google.com/item?q=funpay",
	}
	for _, url := range urls {
		exec.Command("cmd", "/c", "start", "", url).Start()
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Println("  ✓ Additional URLs opened")

	fmt.Println("  Opening Recent folder...")
	recentPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Recent")
	exec.Command("explorer", recentPath).Start()
	fmt.Println("  ✓ Recent folder opened")

	fmt.Println("  Opening Google history...")
	queries := []string{"0x", "leet", "cheats", "1337", "software", "unicore", "amphetamine", "cheat"}
	for _, query := range queries {
		exec.Command("cmd", "/c", "start", "", fmt.Sprintf("https://myactivity.google.com/myactivity?q=%s", query)).Start()
		time.Sleep(30 * time.Millisecond)
	}
	fmt.Println("  ✓ Google history opened")
}

func sendToDiscord(systemInfo, fileSearchResults string) {
	fullReport := systemInfo + fileSearchResults

	for i := 0; i < len(fullReport); i += 2000 {
		end := i + 2000
		if end > len(fullReport) {
			end = len(fullReport)
		}

		chunk := fullReport[i:end]
		sendDiscordMessage(chunk)
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println("  ✓ Full results sent to Discord")
}

func sendDiscordMessage(content string) {
	if discordWebhook == "" {
		return
	}

	message := fmt.Sprintf("```\n%s\n```", content)

	if len(message) > 2000 {
		message = message[:1997] + "```"
	}

	msg := DiscordMessage{
		Content: message,
	}

	jsonData, _ := json.Marshal(msg)
	http.Post(discordWebhook, "application/json", bytes.NewBuffer(jsonData))
}

func clearConsole() {
	cmd := exec.Command("cmd", "/c", "cls")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func executeBatchActionsWithProgress() {
	steps := []struct {
		desc string
		fn   func()
	}{
		{"Setting console color", func() {
			exec.Command("cmd", "/c", "color", "D").Run()
			fmt.Print("✓ ")
		}},
		{"Opening password recovery URLs", func() {
			urls := []string{
				"https://0xcheats.net/auth/forgot/",
				"https://leet-cheats.ru/restore_password",
				"https://unicore.cloud/forum/lost-password/",
				"https://vanish-cheat.com/login",
			}
			for _, url := range urls {
				exec.Command("cmd", "/c", "start", "", url).Start()
				time.Sleep(50 * time.Millisecond)
			}
			fmt.Print("✓ ")
		}},
		{"Pause 2 seconds", func() {
			for i := 2; i > 0; i-- {
				fmt.Printf("%d... ", i)
				time.Sleep(1 * time.Second)
			}
			fmt.Print("✓ ")
		}},
		{"Setting UTF-8 encoding", func() {
			exec.Command("cmd", "/c", "chcp", "65001").Run()
			fmt.Print("✓ ")
		}},
		{"Opening additional URLs", func() {
			urls := []string{
				"https://oplata.info/info/",
				"https://funpay.com/account/login",
				"https://forum.majestic-rp.ru/",
				"https://discord.com/",
				"https://myactivity.google.com/myactivity?hl=ru&pli=1&q=cheat",
				"https://myactivity.google.com/item?q=funpay",
			}
			for _, url := range urls {
				exec.Command("cmd", "/c", "start", "", url).Start()
				time.Sleep(50 * time.Millisecond)
			}
			fmt.Print("✓ ")
		}},
		{"Opening Recent folder", func() {
			recentPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Recent")
			exec.Command("explorer", recentPath).Start()
			fmt.Print("✓ ")
		}},
		{"Opening Google history", func() {
			queries := []string{"0x", "leet", "cheats", "1337", "software", "unicore", "amphetamine", "cheat"}
			for _, query := range queries {
				exec.Command("cmd", "/c", "start", "", fmt.Sprintf("https://myactivity.google.com/myactivity?q=%s", query)).Start()
				time.Sleep(30 * time.Millisecond)
			}
			fmt.Print("✓ ")
		}},
	}

	for i, step := range steps {
		fmt.Printf("\r  [%d/%d] %-40s", i+1, len(steps), step.desc)
		step.fn()
	}
	fmt.Println("\n  ✓ All actions completed!")
}

func collectSystemInfoWithProgress() string {
	var buffer bytes.Buffer

	infoSteps := []struct {
		desc string
		fn   func(*bytes.Buffer)
	}{
		{"Getting system information", collectBasicInfo},
		{"Analyzing last reboot", collectBootInfo},
		{"Checking File Explorer history", collectExplorerInfo},
		{"Determining Windows installation date", collectInstallInfo},
		{"Checking Recycle Bin", collectRecycleBinInfo},
		{"Analyzing Event Logs", collectEventLogInfo},
		{"Searching recent downloads", collectDownloadsInfo},
		{"Scanning disks", collectDiskInfo},
		{"Analyzing USB history", collectUSBHistoryInfo},
		{"Checking connected USB devices", collectConnectedUSBInfo},
		{"Searching for DMA devices", collectDMAInfo},
	}

	fmt.Println("  Collecting information...")

	for i, step := range infoSteps {
		fmt.Printf("\r  [%d/%d] %-35s", i+1, len(infoSteps), step.desc)
		step.fn(&buffer)
		fmt.Print("✓")
		time.Sleep(100 * time.Millisecond) // Небольшая пауза для прогресса
	}

	fmt.Println("\n  ✓ System information collected!")
	return buffer.String()
}

func collectBasicInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("=", 80) + "\n")
	buffer.WriteString("BASIC SYSTEM INFORMATION\n")
	buffer.WriteString(strings.Repeat("=", 80) + "\n")

	buffer.WriteString(fmt.Sprintf("Scan date: %s\n", time.Now().Format("02.01.2006 15:04:05")))
	buffer.WriteString(fmt.Sprintf("User: %s\n", os.Getenv("USERNAME")))
	buffer.WriteString(fmt.Sprintf("Computer: %s\n", os.Getenv("COMPUTERNAME")))
	buffer.WriteString(fmt.Sprintf("Home folder: %s\n", os.Getenv("USERPROFILE")))
	buffer.WriteString("\n")
}

func collectBootInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("1. LAST SYSTEM REBOOT\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	cmd := exec.Command("cmd", "/c", "systeminfo")
	output, _ := cmd.Output()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "System Boot Time") || strings.Contains(line, "Время загрузки системы") {
			buffer.WriteString("  " + strings.TrimSpace(line) + "\n")
		}
	}

	cmd = exec.Command("wmic", "os", "get", "lastbootuptime")
	output, _ = cmd.Output()
	if len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 1 && strings.TrimSpace(lines[1]) != "" {
			timeStr := strings.TrimSpace(lines[1])
			buffer.WriteString(fmt.Sprintf("  Last boot (WMI): %s\n", formatWMITime(timeStr)))
		}
	}
	buffer.WriteString("\n")
}

func collectExplorerInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("2. FILE EXPLORER HISTORY\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	recentPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Recent")
	buffer.WriteString(fmt.Sprintf("  Recent folder: %s\n", recentPath))

	files, err := ioutil.ReadDir(recentPath)
	if err == nil && len(files) > 0 {
		buffer.WriteString(fmt.Sprintf("  Total files: %d\n", len(files)))
		buffer.WriteString("  Last 8 files:\n")

		count := 0
		for i := len(files) - 1; i >= 0 && count < 8; i-- {
			file := files[i]
			buffer.WriteString(fmt.Sprintf("  • %-50s [%s]\n", truncateString(file.Name(), 45), file.ModTime().Format("02.01 15:04")))
			count++
		}
	}
	buffer.WriteString("\n")
}

func collectInstallInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("3. WINDOWS INFORMATION\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()

		if installTime, _, err := k.GetIntegerValue("InstallDate"); err == nil {
			t := time.Unix(int64(installTime), 0)
			buffer.WriteString(fmt.Sprintf("  Installation date: %s\n", t.Format("02.01.2006 15:04:05")))
			days := int(time.Since(t).Hours() / 24)
			buffer.WriteString(fmt.Sprintf("  Installed days ago: %d\n", days))
		}

		if productName, _, err := k.GetStringValue("ProductName"); err == nil {
			buffer.WriteString(fmt.Sprintf("  Version: %s\n", productName))
		}

		if buildNumber, _, err := k.GetStringValue("CurrentBuildNumber"); err == nil {
			buffer.WriteString(fmt.Sprintf("  Build: %s\n", buildNumber))
		}
	}
	buffer.WriteString("\n")
}

func collectRecycleBinInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("4. RECYCLE BIN\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	recyclePath := "C:\\$Recycle.Bin"
	if _, err := os.Stat(recyclePath); err == nil {
		files, err := ioutil.ReadDir(recyclePath)
		if err == nil {
			userCount := 0
			totalSize := int64(0)
			var latestTime time.Time

			for _, file := range files {
				if file.IsDir() && len(file.Name()) > 5 {
					userCount++
					userPath := filepath.Join(recyclePath, file.Name())
					if size, err := dirSize(userPath); err == nil {
						totalSize += size
					}
					if file.ModTime().After(latestTime) {
						latestTime = file.ModTime()
					}
				}
			}

			buffer.WriteString(fmt.Sprintf("  User folders: %d\n", userCount))
			if totalSize > 0 {
				sizeMB := float64(totalSize) / (1024 * 1024)
				buffer.WriteString(fmt.Sprintf("  Approximate size: %.2f MB\n", sizeMB))
			}

			if !latestTime.IsZero() {
				buffer.WriteString(fmt.Sprintf("  Last modified: %s\n", latestTime.Format("02.01.2006 15:04:05")))
				daysAgo := int(time.Since(latestTime).Hours() / 24)
				buffer.WriteString(fmt.Sprintf("  Recycle Bin was modified %d days ago\n", daysAgo))
			}
		}
	} else {
		buffer.WriteString("  No access to Recycle Bin information\n")
	}

	buffer.WriteString("\n  Additional information:\n")
	cmd := exec.Command("reg", "query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket", "/v", "NukeOnDelete")
	output, _ := cmd.Output()
	if strings.Contains(string(output), "0x1") {
		buffer.WriteString("  Auto-clean Recycle Bin: ENABLED\n")
	} else if strings.Contains(string(output), "0x0") {
		buffer.WriteString("  Auto-clean Recycle Bin: DISABLED\n")
	}

	buffer.WriteString("\n")
}

func collectEventLogInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("5. EVENT LOGS\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	logs := []struct {
		name string
		desc string
	}{
		{"System", "System events"},
		{"Security", "Security events"},
		{"Application", "Application events"},
	}

	for _, log := range logs {
		cmd := exec.Command("wevtutil", "gli", log.name)
		output, _ := cmd.Output()
		lines := strings.Split(string(output), "\n")

		for _, line := range lines {
			if strings.Contains(line, "lastWriteTime:") {
				if parts := strings.Split(line, "lastWriteTime:"); len(parts) > 1 {
					timeStr := strings.TrimSpace(parts[1])
					buffer.WriteString(fmt.Sprintf("  %s updated: %s\n", log.desc, timeStr))
				}
			}
		}
	}
	buffer.WriteString("\n")
}

func collectDownloadsInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("6. RECENT DOWNLOADS\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	downloadsPath := filepath.Join(os.Getenv("USERPROFILE"), "Downloads")
	buffer.WriteString(fmt.Sprintf("  Downloads folder: %s\n", downloadsPath))

	files, err := ioutil.ReadDir(downloadsPath)
	if err == nil && len(files) > 0 {
		buffer.WriteString("  Last 5 files:\n")

		count := 0
		for i := len(files) - 1; i >= 0 && count < 5; i-- {
			file := files[i]
			if !file.IsDir() {
				sizeMB := float64(file.Size()) / (1024 * 1024)
				buffer.WriteString(fmt.Sprintf("  • %-40s %6.1f MB [%s]\n", truncateString(file.Name(), 35), sizeMB, file.ModTime().Format("02.01 15:04")))
				count++
			}
		}
	}
	buffer.WriteString("\n")
}

func collectDiskInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("7. DISK INFORMATION\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	cmd := exec.Command("powershell", "-Command",
		`Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | `+
			`Select-Object DeviceID, Size, FreeSpace, VolumeName | `+
			`ForEach-Object { "{0}|{1}|{2}|{3}" -f $_.DeviceID, $_.Size, $_.FreeSpace, $_.VolumeName }`)
	output, _ := cmd.Output()

	if len(output) > 0 {
		buffer.WriteString("  Logical drives:\n")
		lines := strings.Split(strings.TrimSpace(string(output)), "\r\n")

		for _, line := range lines {
			parts := strings.Split(line, "|")
			if len(parts) >= 4 {
				drive := strings.TrimSpace(parts[0])
				sizeStr := strings.TrimSpace(parts[1])
				freeStr := strings.TrimSpace(parts[2])
				volumeName := strings.TrimSpace(parts[3])

				sizeGB := parseByteSize(sizeStr)
				freeGB := parseByteSize(freeStr)

				if volumeName == "" {
					volumeName = "Local Disk"
				}

				if sizeGB > 0 {
					usedGB := sizeGB - freeGB
					percentUsed := int((usedGB / sizeGB) * 100)
					buffer.WriteString(fmt.Sprintf("    %s (%s): %5.1f GB / %5.1f GB (%d%% used)\n", drive, volumeName, usedGB, sizeGB, percentUsed))
				} else if sizeStr != "" && sizeStr != "0" {
					buffer.WriteString(fmt.Sprintf("    %s (%s): Size %s bytes\n", drive, volumeName, formatByteString(sizeStr)))
				}
			}
		}
	} else {
		buffer.WriteString("  Logical drives (via wmic):\n")
		cmd = exec.Command("wmic", "logicaldisk", "where", "drivetype=3", "get", "DeviceID,Size,FreeSpace,VolumeName", "/format:list")
		output, _ = cmd.Output()

		lines := strings.Split(string(output), "\r\n")
		var drive, sizeStr, freeStr, volumeName string

		for _, line := range lines {
			if strings.HasPrefix(line, "DeviceID=") {
				drive = strings.TrimPrefix(line, "DeviceID=")
			} else if strings.HasPrefix(line, "Size=") {
				sizeStr = strings.TrimPrefix(line, "Size=")
			} else if strings.HasPrefix(line, "FreeSpace=") {
				freeStr = strings.TrimPrefix(line, "FreeSpace=")
			} else if strings.HasPrefix(line, "VolumeName=") {
				volumeName = strings.TrimPrefix(line, "VolumeName=")
			}

			if drive != "" && sizeStr != "" && freeStr != "" {
				sizeGB := parseByteSize(sizeStr)
				freeGB := parseByteSize(freeStr)

				if volumeName == "" {
					volumeName = "Local Disk"
				}

				if sizeGB > 0 {
					usedGB := sizeGB - freeGB
					percentUsed := int((usedGB / sizeGB) * 100)
					buffer.WriteString(fmt.Sprintf("    %s (%s): %5.1f GB / %5.1f GB (%d%% used)\n", drive, volumeName, usedGB, sizeGB, percentUsed))
				}

				drive, sizeStr, freeStr, volumeName = "", "", "", ""
			}
		}
	}

	buffer.WriteString("\n")
}

func collectUSBHistoryInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("8. USB DEVICE HISTORY\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	cmd := exec.Command("reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "/s")
	output, _ := cmd.Output()

	devices := make(map[string]bool)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "FriendlyName") {
			parts := strings.Split(line, "REG_SZ")
			if len(parts) > 1 {
				deviceName := strings.TrimSpace(parts[1])
				if !devices[deviceName] {
					devices[deviceName] = true
				}
			}
		}
	}

	if len(devices) > 0 {
		buffer.WriteString(fmt.Sprintf("  Total unique devices: %d\n", len(devices)))
		buffer.WriteString("  Device examples:\n")
		count := 0
		for device := range devices {
			if count < 5 {
				buffer.WriteString(fmt.Sprintf("    • %s\n", truncateString(device, 60)))
				count++
			}
		}
		if len(devices) > 5 {
			buffer.WriteString(fmt.Sprintf("    ... and %d more devices\n", len(devices)-5))
		}
	} else {
		buffer.WriteString("  No USB device information found\n")
	}
	buffer.WriteString("\n")
}

func collectConnectedUSBInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("9. CONNECTED USB DEVICES\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	cmd := exec.Command("wmic", "path", "Win32_USBHub", "get", "DeviceID,Description")
	output, _ := cmd.Output()

	connectedCount := 0
	if len(output) > 0 {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "USB") && !strings.Contains(line, "DeviceID") && strings.TrimSpace(line) != "" {
				buffer.WriteString(fmt.Sprintf("    %s\n", truncateString(strings.TrimSpace(line), 70)))
				connectedCount++
			}
		}
	}

	if connectedCount == 0 {
		buffer.WriteString("    No connected USB devices\n")
	} else {
		buffer.WriteString(fmt.Sprintf("\n    Total connected: %d devices\n", connectedCount))
	}
	buffer.WriteString("\n")
}

func collectDMAInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("10. DMA DEVICE CHECK\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	cmd := exec.Command("wmic", "path", "Win32_PnPEntity", "get", "Name,Description", "/format:csv")
	output, _ := cmd.Output()

	foundDMA := false
	if len(output) > 0 {
		reader := csv.NewReader(bytes.NewReader(output))
		records, _ := reader.ReadAll()

		for _, record := range records {
			if len(record) >= 2 {
				name := record[0]
				up := strings.ToUpper(name)

				if strings.Contains(up, "1394") ||
					strings.Contains(up, "FIREWIRE") ||
					strings.Contains(up, "THUNDERBOLT") ||
					strings.Contains(up, "PCI") ||
					strings.Contains(up, "EXPRESS CARD") {
					buffer.WriteString(fmt.Sprintf("    POSSIBLE DMA: %s\n", name))
					foundDMA = true
				}
			}
		}
	}

	if !foundDMA {
		buffer.WriteString("    No obvious DMA devices found\n")
	}
	buffer.WriteString("\n")
}

func searchSuspiciousFilesWithProgress() string {
	var buffer bytes.Buffer

	buffer.WriteString(strings.Repeat("=", 80) + "\n")
	buffer.WriteString("SUSPICIOUS FILE SEARCH RESULTS\n")
	buffer.WriteString(strings.Repeat("=", 80) + "\n")

	suspiciousPatterns := []struct {
		pattern *regexp.Regexp
		desc    string
		score   int
	}{
		{regexp.MustCompile(`(?i)(cheat|hack|wallhack|aimbot|triggerbot|esp|radar|spoofer|spoof)\.(exe|dll|sys|bat)$`), "Game cheat", 10},
		{regexp.MustCompile(`(?i)(inject|load)er[0-9]*\.(exe|dll)$`), "Injector", 9},
		{regexp.MustCompile(`(?i)(bypass|anti.?detect|anti.?cheat)\.(exe|dll)$`), "Anti-detection", 9},

		{regexp.MustCompile(`(?i)(0x|leet|1337|unicore|vanish|amphetamine|fortnite|apex|warzone|valorant|csgo|cs2)cheat`), "Cheat name", 8},
		{regexp.MustCompile(`(?i)(rage|legit|silent|undetected)\.(exe|dll)$`), "Cheat type", 7},

		{regexp.MustCompile(`(?i)(process.?hacker|process.?explorer|cheat.?engine|debugger)\.(exe|dll)$`), "System tool", 6},
		{regexp.MustCompile(`(?i)(memory.?editor|ram.?editor|hex.?editor)\.(exe|dll)$`), "Memory editor", 7},

		{regexp.MustCompile(`(?i)(crack|patch|keygen|serial|activator)\.(exe|rar|zip|7z)$`), "Software crack", 8},
		{regexp.MustCompile(`(?i)(steam.?api|dinput|xlive)\.(dll|ini)$`), "API replacement", 7},

		{regexp.MustCompile(`^[a-f0-9]{16,}\.(exe|dll|sys|bin)$`), "Hex random name", 9},
		{regexp.MustCompile(`^[a-z0-9]{20,}\.(exe|dll|sys)$`), "Long random name", 8},
		{regexp.MustCompile(`^_[a-z0-9]{10,}\.(exe|dll)$`), "Underscored random", 7},

		{regexp.MustCompile(`^[a-z0-9]{8,}\.(rar|zip|7z|tar|gz)$`), "Random archive", 6},
		{regexp.MustCompile(`(?i)(release|build|final|beta|alpha|test)\.(rar|zip|7z)$`), "Dev archive", 5},

		{regexp.MustCompile(`(?i)(driver|sys)\.sys$`), "Suspicious driver", 8},
		{regexp.MustCompile(`(?i)(obfuscated|encrypted|packed)\.(exe|dll)$`), "Obfuscated", 7},
	}

	extensions := []string{".exe", ".dll", ".rar", ".zip", ".7z", ".bin", ".sys", ".ahk"}
	totalSuspicious := 0
	resultsByDrive := make(map[string][]string)

	var drives []string
	for drive := 'A'; drive <= 'Z'; drive++ {
		driveLetter := string(drive)
		drivePath := driveLetter + ":\\"
		if _, err := os.Stat(drivePath); err == nil {
			drives = append(drives, driveLetter)
		}
	}

	driveChan := make(chan string, len(drives))
	resultChan := make(chan struct {
		drive string
		files []string
		count int
	}, len(drives))

	var wg sync.WaitGroup
	numWorkers := 4

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for drive := range driveChan {
				foundFiles, count := searchDriveForSuspiciousFiles(drive, extensions, suspiciousPatterns)
				resultChan <- struct {
					drive string
					files []string
					count int
				}{drive, foundFiles, count}
			}
		}()
	}

	go func() {
		for _, drive := range drives {
			driveChan <- drive
		}
		close(driveChan)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	fmt.Println("  Searching on drives...")
	currentDrive := 0

	for result := range resultChan {
		currentDrive++
		fmt.Printf("\r  Drive %s [%d/%d] found %d files", result.drive, currentDrive, len(drives), result.count)

		totalSuspicious += result.count
		if result.count > 0 {
			resultsByDrive[result.drive] = result.files
		}
	}

	fmt.Print("\r  " + strings.Repeat(" ", 50) + "\r")

	if totalSuspicious > 0 {
		buffer.WriteString(fmt.Sprintf("\nFOUND SUSPICIOUS FILES: %d\n\n", totalSuspicious))

		for drive, files := range resultsByDrive {
			driveLabel := getDriveLabel(drive)
			buffer.WriteString(fmt.Sprintf("Drive %s: (%s)\n", drive, driveLabel))
			buffer.WriteString(strings.Repeat("-", 40) + "\n")

			for _, file := range files {
				buffer.WriteString(fmt.Sprintf("  %s\n", file))
			}
			buffer.WriteString("\n")
		}
	} else {
		buffer.WriteString("\nNo suspicious files found.\n")
	}

	buffer.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("-", 80)))
	return buffer.String()
}

func searchDriveForSuspiciousFiles(drive string, extensions []string, patterns []struct {
	pattern *regexp.Regexp
	desc    string
	score   int
}) ([]string, int) {
	var foundFiles []string
	fileScores := make(map[string]int)
	drivePath := drive + ":\\"

	for _, ext := range extensions {
		cmd := exec.Command("cmd", "/c", "dir", "/b", "/s", "/a-d", drivePath+"*"+ext)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		lines := strings.Split(string(output), "\r\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			fileName := filepath.Base(line)
			filePath := line

			for _, pattern := range patterns {
				if pattern.pattern.MatchString(strings.ToLower(fileName)) {
					if fileScores[filePath] < pattern.score {
						fileScores[filePath] = pattern.score
					}
				}
			}

			nameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))
			if isRandomString(nameWithoutExt) {
				if fileScores[filePath] < 6 {
					fileScores[filePath] = 6
				}
			}

			if info, err := os.Stat(filePath); err == nil {
				sizeMB := float64(info.Size()) / (1024 * 1024)
				ext := strings.ToLower(filepath.Ext(fileName))
				if ext == ".exe" || ext == ".dll" {
					if sizeMB < 0.1 || sizeMB > 500 {
						if fileScores[filePath] < 5 {
							fileScores[filePath] = 5
						}
					}
				}
			}
		}
	}

	for filePath, score := range fileScores {
		fileName := filepath.Base(filePath)
		if score >= 5 {
			foundFiles = append(foundFiles, fmt.Sprintf("%-50s [Score: %d]", truncateString(fileName, 45), score))
		}
	}

	sort.Slice(foundFiles, func(i, j int) bool {
		scoreI := extractScore(foundFiles[i])
		scoreJ := extractScore(foundFiles[j])
		return scoreI > scoreJ
	})

	if len(foundFiles) > 100 {
		foundFiles = foundFiles[:100]
	}

	return foundFiles, len(foundFiles)
}

func extractScore(entry string) int {
	parts := strings.Split(entry, "Score: ")
	if len(parts) > 1 {
		scoreStr := strings.TrimSuffix(parts[1], "]")
		if score, err := strconv.Atoi(scoreStr); err == nil {
			return score
		}
	}
	return 0
}

func getDriveLabel(drive string) string {
	cmd := exec.Command("wmic", "logicaldisk", "where", fmt.Sprintf("name='%s:'", drive), "get", "volumename", "/value")
	output, _ := cmd.Output()

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VolumeName=") {
			label := strings.TrimPrefix(line, "VolumeName=")
			label = strings.TrimSpace(label)
			if label == "" {
				return "Local Disk"
			}
			return label
		}
	}
	return "Local Disk"
}

func isRandomString(s string) bool {
	if len(s) < 8 {
		return false
	}

	digitCount := 0
	letterCount := 0
	lowerCount := 0
	upperCount := 0
	specialCount := 0
	vowelCount := 0
	consonantCount := 0

	vowels := "aeiouyAEIOUYаеёиоуыэюяАЕЁИОУЫЭЮЯ"
	consonants := "bcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZбвгджзйклмнпрстфхцчшщБВГДЖЗЙКЛМНПРСТФХЦЧШЩ"

	var lastChar rune
	repeatThreshold := 0

	for i, c := range s {
		if c >= '0' && c <= '9' {
			digitCount++
		} else if c >= 'a' && c <= 'z' {
			letterCount++
			lowerCount++
			if strings.ContainsRune(vowels, c) {
				vowelCount++
			} else if strings.ContainsRune(consonants, c) {
				consonantCount++
			}
		} else if c >= 'A' && c <= 'Z' {
			letterCount++
			upperCount++
			if strings.ContainsRune(vowels, c) {
				vowelCount++
			} else if strings.ContainsRune(consonants, c) {
				consonantCount++
			}
		} else {
			specialCount++
		}

		if i > 0 && c == lastChar {
			repeatThreshold++
		}
		lastChar = c
	}

	totalChars := len(s)

	score := 0

	if float64(digitCount)/float64(totalChars) > 0.3 {
		score += 3
	}

	if letterCount > 10 && float64(vowelCount)/float64(letterCount) < 0.1 {
		score += 3
	}

	if repeatThreshold > totalChars/3 {
		score += 2
	}

	if letterCount > 15 && (lowerCount == 0 || upperCount == 0) {
		score += 2
	}

	if consonantCount > 5 && vowelCount > 2 {
		naturalPattern := float64(consonantCount) / float64(vowelCount)
		if naturalPattern >= 1.5 && naturalPattern <= 4.0 {
			score -= 2
		}
	}

	return score >= 3
}

func showFinalReport(systemInfo, fileSearchResults string) {
	clearConsole()

	fmt.Println("╔══════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                         COMPLETE SYSTEM REPORT                           ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Print(systemInfo)
	fmt.Print(fileSearchResults)

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("ADDITIONAL INFORMATION")
	fmt.Println(strings.Repeat("=", 80))

	fullReport := systemInfo + fileSearchResults
	desktopPath := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	reportPath := filepath.Join(desktopPath, "system_report.txt")

	if err := ioutil.WriteFile(reportPath, []byte(fullReport), 0644); err == nil {
		fmt.Printf("✓ Full report saved: %s\n", reportPath)

		extraInfo := collectExtraInfo()
		completeReport := fullReport + "\n" + extraInfo
		ioutil.WriteFile(reportPath, []byte(completeReport), 0644)
	} else {
		fmt.Printf("✗ Error saving report: %v\n", err)
	}

	fmt.Println("\nActive network connections:")
	cmd := exec.Command("netstat", "-ano")
	output, _ := cmd.Output()
	fmt.Print(string(output[:min(len(output), 1000)]))

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("SCAN COMPLETED!")
}

func collectExtraInfo() string {
	var buffer bytes.Buffer

	buffer.WriteString("\n" + strings.Repeat("=", 80) + "\n")
	buffer.WriteString("ADDITIONAL SYSTEM DATA\n")
	buffer.WriteString(strings.Repeat("=", 80) + "\n\n")

	buffer.WriteString("RUNNING PROCESSES:\n")
	buffer.WriteString(strings.Repeat("-", 40) + "\n")
	cmd := exec.Command("tasklist")
	output, _ := cmd.Output()
	buffer.Write(output)

	buffer.WriteString("\nSTARTUP PROGRAMS:\n")
	buffer.WriteString(strings.Repeat("-", 40) + "\n")
	cmd = exec.Command("wmic", "startup", "get", "caption,command")
	output, _ = cmd.Output()
	buffer.Write(output)

	buffer.WriteString("\nSERVICES (first 20):\n")
	buffer.WriteString(strings.Repeat("-", 40) + "\n")
	cmd = exec.Command("sc", "query", "type=", "service", "state=", "all")
	output, _ = cmd.Output()
	lines := strings.Split(string(output), "\n")
	count := 0
	for _, line := range lines {
		if strings.Contains(line, "SERVICE_NAME") && count < 20 {
			buffer.WriteString(line + "\n")
			count++
		}
	}

	return buffer.String()
}

func formatWMITime(wmiTime string) string {
	if len(wmiTime) >= 14 {
		year := wmiTime[0:4]
		month := wmiTime[4:6]
		day := wmiTime[6:8]
		hour := wmiTime[8:10]
		minute := wmiTime[10:12]
		second := wmiTime[12:14]
		return fmt.Sprintf("%s.%s.%s %s:%s:%s", day, month, year, hour, minute, second)
	}
	return wmiTime
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func parseByteSize(sizeStr string) float64 {
	if sizeStr == "" {
		return 0
	}

	sizeStr = strings.TrimSpace(sizeStr)
	var cleaned strings.Builder
	for _, r := range sizeStr {
		if r >= '0' && r <= '9' {
			cleaned.WriteRune(r)
		}
	}

	cleanedStr := cleaned.String()
	if cleanedStr == "" {
		return 0
	}

	var size int64
	_, err := fmt.Sscanf(cleanedStr, "%d", &size)
	if err != nil {
		return 0
	}

	return float64(size) / (1024 * 1024 * 1024)
}

func formatByteString(sizeStr string) string {
	sizeGB := parseByteSize(sizeStr)
	if sizeGB >= 1 {
		return fmt.Sprintf("%.2f GB", sizeGB)
	}

	sizeMB := sizeGB * 1024
	if sizeMB >= 1 {
		return fmt.Sprintf("%.2f MB", sizeMB)
	}

	sizeKB := sizeMB * 1024
	if sizeKB >= 1 {
		return fmt.Sprintf("%.2f KB", sizeKB)
	}

	return fmt.Sprintf("%.0f bytes", sizeKB*1024)
}

func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
