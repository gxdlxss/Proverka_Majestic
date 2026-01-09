package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

func main() {
	// Start execution
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║               SYSTEM SCANNER - STARTUP                  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	// Perform all actions with progress display
	fmt.Println("\n[1/3] EXECUTING DEFAULT ACTIONS...")
	executeBatchActionsWithProgress()

	fmt.Println("\n[2/3] COLLECTING SYSTEM INFORMATION...")
	systemInfo := collectSystemInfoWithProgress()

	fmt.Println("\n[3/3] SEARCHING FOR SUSPICIOUS FILES...")
	fileSearchResults := searchSuspiciousFilesWithProgress()

	// Clear console and show results
	clearConsole()
	showFinalReport(systemInfo, fileSearchResults)

	// Wait before exit
	fmt.Print("\n\nPress Enter to exit...")
	fmt.Scanln()
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
				exec.Command("cmd", "/c", "start", "",
					fmt.Sprintf("https://myactivity.google.com/myactivity?q=%s", query)).Start()
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

	// Start information collection in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex

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

	// Channel for tracking progress
	progressChan := make(chan string, len(infoSteps))

	fmt.Println("  Collecting information...")

	// Start all steps in parallel
	for i, step := range infoSteps {
		wg.Add(1)
		go func(idx int, desc string, fn func(*bytes.Buffer)) {
			defer wg.Done()

			// Execute data collection function
			mu.Lock()
			fn(&buffer)
			mu.Unlock()

			// Send result to channel
			progressChan <- fmt.Sprintf("[%d/%d] %-35s✓", idx+1, len(infoSteps), desc)
		}(i, step.desc, step.fn)
	}

	// Track progress
	go func() {
		wg.Wait()
		close(progressChan)
	}()

	// Display progress
	for progress := range progressChan {
		fmt.Printf("\r  %s", progress)
	}

	fmt.Println("\n  ✓ System information collected!")
	return buffer.String()
}

func collectBasicInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("=", 80) + "\n")
	buffer.WriteString("BASIC SYSTEM INFORMATION\n")
	buffer.WriteString(strings.Repeat("=", 80) + "\n")

	buffer.WriteString(fmt.Sprintf("Scan date: %s\n",
		time.Now().Format("02.01.2006 15:04:05")))
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
		if strings.Contains(line, "System Boot Time") ||
			strings.Contains(line, "Время загрузки системы") {
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
			buffer.WriteString(fmt.Sprintf("  • %-50s [%s]\n",
				truncateString(file.Name(), 45),
				file.ModTime().Format("02.01 15:04")))
			count++
		}
	}
	buffer.WriteString("\n")
}

func collectInstallInfo(buffer *bytes.Buffer) {
	buffer.WriteString(strings.Repeat("-", 80) + "\n")
	buffer.WriteString("3. WINDOWS INFORMATION\n")
	buffer.WriteString(strings.Repeat("-", 80) + "\n")

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()

		if installTime, _, err := k.GetIntegerValue("InstallDate"); err == nil {
			t := time.Unix(int64(installTime), 0)
			buffer.WriteString(fmt.Sprintf("  Installation date: %s\n",
				t.Format("02.01.2006 15:04:05")))

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
					// Try to get folder size
					userPath := filepath.Join(recyclePath, file.Name())
					if size, err := dirSize(userPath); err == nil {
						totalSize += size
					}

					// Check modification time
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
				buffer.WriteString(fmt.Sprintf("  Last modified: %s\n",
					latestTime.Format("02.01.2006 15:04:05")))
				daysAgo := int(time.Since(latestTime).Hours() / 24)
				buffer.WriteString(fmt.Sprintf("  Recycle Bin was modified %d days ago\n", daysAgo))
			}
		}
	} else {
		buffer.WriteString("  No access to Recycle Bin information\n")
	}

	// Additional check via registry
	buffer.WriteString("\n  Additional information:\n")
	cmd := exec.Command("reg", "query",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket",
		"/v", "NukeOnDelete")
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
				buffer.WriteString(fmt.Sprintf("  • %-40s %6.1f MB [%s]\n",
					truncateString(file.Name(), 35),
					sizeMB,
					file.ModTime().Format("02.01 15:04")))
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

	// Use PowerShell command for more reliable information retrieval
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

				// Clean numeric strings
				sizeGB := parseByteSize(sizeStr)
				freeGB := parseByteSize(freeStr)

				if volumeName == "" {
					volumeName = "Local Disk"
				}

				if sizeGB > 0 {
					usedGB := sizeGB - freeGB
					percentUsed := int((usedGB / sizeGB) * 100)
					buffer.WriteString(fmt.Sprintf("    %s (%s): %5.1f GB / %5.1f GB (%d%% used)\n",
						drive, volumeName, usedGB, sizeGB, percentUsed))
				} else if sizeStr != "" && sizeStr != "0" {
					buffer.WriteString(fmt.Sprintf("    %s (%s): Size %s bytes\n",
						drive, volumeName, formatByteString(sizeStr)))
				}
			}
		}
	} else {
		// Fallback to wmic if PowerShell doesn't work
		buffer.WriteString("  Logical drives (via wmic):\n")
		cmd = exec.Command("wmic", "logicaldisk", "where", "drivetype=3",
			"get", "DeviceID,Size,FreeSpace,VolumeName", "/format:list")
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

			// When we found all data for a drive
			if drive != "" && sizeStr != "" && freeStr != "" {
				sizeGB := parseByteSize(sizeStr)
				freeGB := parseByteSize(freeStr)

				if volumeName == "" {
					volumeName = "Local Disk"
				}

				if sizeGB > 0 {
					usedGB := sizeGB - freeGB
					percentUsed := int((usedGB / sizeGB) * 100)
					buffer.WriteString(fmt.Sprintf("    %s (%s): %5.1f GB / %5.1f GB (%d%% used)\n",
						drive, volumeName, usedGB, sizeGB, percentUsed))
				}

				// Reset for next drive
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

	cmd := exec.Command("reg", "query",
		"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "/s")
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
			if strings.Contains(line, "USB") &&
				!strings.Contains(line, "DeviceID") &&
				strings.TrimSpace(line) != "" {
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

				// Look for DMA device signs
				if strings.Contains(strings.ToUpper(name), "1394") ||
					strings.Contains(strings.ToUpper(name), "FIREWIRE") ||
					strings.Contains(strings.ToUpper(name), "THUNDERBOLT") ||
					strings.Contains(strings.ToUpper(name), "PCI") ||
					strings.Contains(strings.ToUpper(name), "EXPRESS CARD") {
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

	// Define suspicious file patterns
	suspiciousPatterns := []struct {
		pattern *regexp.Regexp
		desc    string
	}{
		// Random filenames (like dfskdfjsj23jr2rj3bhbasrfj3b4tbh3bgql)
		{regexp.MustCompile(`^[a-f0-9]{16,}(\.(exe|dll|rar|zip|7z|bin))?$`), "Random name"},
		{regexp.MustCompile(`^[a-z0-9]{20,}\.(exe|dll|sys|bin)$`), "Long random name"},

		// Files related to cheats
		{regexp.MustCompile(`(?i)(cheat|hack|inject|spoof|bypass|loader|injector|trainer)\.(exe|dll)$`), "Cheat/Hack"},
		{regexp.MustCompile(`(?i)(0x|leet|1337|unicore|vanish|amphetamine|fortnite|apex|cod|valorant)\.(exe|dll)$`), "Cheat name"},
		{regexp.MustCompile(`(?i)(wallhack|aimbot|triggerbot|esp|radar)\.(exe|dll)$`), "Cheat functions"},
		{regexp.MustCompile(`(?i)(inject|load)er\d*\.(exe|dll)$`), "Injector"},
		{regexp.MustCompile(`(?i)antidetect\.(exe|dll)$`), "Anti-detect"},

		// Suspicious archives
		{regexp.MustCompile(`(?i)release|build|final|crack|patch|keygen|serial\.(rar|zip|7z)$`), "Crack/Patch"},
		{regexp.MustCompile(`^[a-z0-9]{8,}\.(rar|zip|7z)$`), "Random archive"},

		// Other suspicious files
		{regexp.MustCompile(`(?i)steam_api\.(dll|ini)$`), "Steam API replacement"},
		{regexp.MustCompile(`(?i)dinput\.(dll|ini)$`), "DirectInput replacement"},
		{regexp.MustCompile(`^_[a-z0-9]{10,}\.(exe|dll)$`), "Underscored file"},
	}

	extensions := []string{".exe", ".dll", ".rar", ".zip", ".7z", ".bin", ".sys", ".ahk"}
	totalSuspicious := 0
	resultsByDrive := make(map[string][]string)

	// Count available drives
	var drives []string
	for drive := 'A'; drive <= 'Z'; drive++ {
		driveLetter := string(drive)
		drivePath := driveLetter + ":\\"
		if _, err := os.Stat(drivePath); err == nil {
			drives = append(drives, driveLetter)
		}
	}

	// Create channels for parallel processing
	driveChan := make(chan string, len(drives))
	resultChan := make(chan struct {
		drive string
		files []string
		count int
	}, len(drives))

	// Start workers for file search
	var wg sync.WaitGroup
	numWorkers := 4 // Number of parallel workers

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

	// Send drives to channel
	go func() {
		for _, drive := range drives {
			driveChan <- drive
		}
		close(driveChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results with progress
	fmt.Println("  Searching on drives...")
	currentDrive := 0

	for result := range resultChan {
		currentDrive++
		fmt.Printf("\r  Drive %s [%d/%d] found %d files",
			result.drive, currentDrive, len(drives), result.count)

		totalSuspicious += result.count
		if result.count > 0 {
			resultsByDrive[result.drive] = result.files
		}
	}

	fmt.Print("\r  " + strings.Repeat(" ", 50) + "\r")

	// Write results to buffer
	if totalSuspicious > 0 {
		buffer.WriteString(fmt.Sprintf("\nFOUND SUSPICIOUS FILES: %d\n\n", totalSuspicious))

		for drive, files := range resultsByDrive {
			// Get drive label
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

	// Summary by file types
	buffer.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("-", 80)))

	return buffer.String()
}

func searchDriveForSuspiciousFiles(drive string, extensions []string, patterns []struct {
	pattern *regexp.Regexp
	desc    string
}) ([]string, int) {
	var foundFiles []string
	drivePath := drive + ":\\"

	// Search files using dir (faster than filesystem traversal in Go)
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

			// Check file against all patterns
			for _, pattern := range patterns {
				if pattern.pattern.MatchString(strings.ToLower(fileName)) {
					foundFiles = append(foundFiles, fmt.Sprintf("%-50s [%s]",
						truncateString(fileName, 45), pattern.desc))
					break // File already classified
				}
			}

			// Also check long names without numbers and letters in random order
			if len(fileName) > 20 {
				// Remove extension for checking
				nameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))
				if isRandomString(nameWithoutExt) {
					foundFiles = append(foundFiles, fmt.Sprintf("%-50s [Random name]",
						truncateString(fileName, 45)))
				}
			}

			// Limit number of files per drive for performance
			if len(foundFiles) >= 100 {
				return foundFiles, len(foundFiles)
			}
		}
	}

	return foundFiles, len(foundFiles)
}

func getDriveLabel(drive string) string {
	cmd := exec.Command("wmic", "logicaldisk", "where", fmt.Sprintf("name='%s:'", drive),
		"get", "volumename", "/value")
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
	// Check if string is a random set of characters
	// Count digit to letter ratio
	if len(s) < 10 {
		return false
	}

	digitCount := 0
	letterCount := 0
	lowerCount := 0
	upperCount := 0

	for _, c := range s {
		if c >= '0' && c <= '9' {
			digitCount++
		} else if c >= 'a' && c <= 'z' {
			letterCount++
			lowerCount++
		} else if c >= 'A' && c <= 'Z' {
			letterCount++
			upperCount++
		}
	}

	totalChars := len(s)

	// If many digits relative to letters
	if totalChars > 0 && float64(digitCount)/float64(totalChars) > 0.3 {
		return true
	}

	// If all letters in one case
	if letterCount > 10 && (lowerCount == 0 || upperCount == 0) {
		return true
	}

	// If no vowels in long enough string
	if totalChars > 15 {
		vowelCount := 0
		vowels := "aeiouyAEIOUYаеёиоуыэюяАЕЁИОУЫЭЮЯ"
		for _, c := range s {
			if strings.ContainsRune(vowels, c) {
				vowelCount++
			}
		}
		if float64(vowelCount)/float64(totalChars) < 0.1 {
			return true
		}
	}

	return false
}

func showFinalReport(systemInfo, fileSearchResults string) {
	// Clear console one more time just in case
	clearConsole()

	// Display report header
	fmt.Println("╔══════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                         COMPLETE SYSTEM REPORT                          ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Display collected information
	fmt.Print(systemInfo)
	fmt.Print(fileSearchResults)

	// Display file save information
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("ADDITIONAL INFORMATION")
	fmt.Println(strings.Repeat("=", 80))

	// Save full report to file
	fullReport := systemInfo + fileSearchResults
	desktopPath := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	reportPath := filepath.Join(desktopPath, "system_report.txt")

	if err := ioutil.WriteFile(reportPath, []byte(fullReport), 0644); err == nil {
		fmt.Printf("✓ Full report saved: %s\n", reportPath)

		// Add additional information to file
		extraInfo := collectExtraInfo()
		completeReport := fullReport + "\n" + extraInfo
		ioutil.WriteFile(reportPath, []byte(completeReport), 0644)
	} else {
		fmt.Printf("✗ Error saving report: %v\n", err)
	}

	// Network connections
	fmt.Println("\nActive network connections:")
	cmd := exec.Command("netstat", "-ano")
	output, _ := cmd.Output()
	fmt.Print(string(output[:min(len(output), 1000)])) // Limit output

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("SCAN COMPLETED!")
}

func collectExtraInfo() string {
	var buffer bytes.Buffer

	buffer.WriteString("\n" + strings.Repeat("=", 80) + "\n")
	buffer.WriteString("ADDITIONAL SYSTEM DATA\n")
	buffer.WriteString(strings.Repeat("=", 80) + "\n\n")

	// Processes
	buffer.WriteString("RUNNING PROCESSES:\n")
	buffer.WriteString(strings.Repeat("-", 40) + "\n")
	cmd := exec.Command("tasklist")
	output, _ := cmd.Output()
	buffer.Write(output)

	// Startup
	buffer.WriteString("\nSTARTUP PROGRAMS:\n")
	buffer.WriteString(strings.Repeat("-", 40) + "\n")
	cmd = exec.Command("wmic", "startup", "get", "caption,command")
	output, _ = cmd.Output()
	buffer.Write(output)

	// Services
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

// Helper functions
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

	// Remove all non-numeric characters except digits
	sizeStr = strings.TrimSpace(sizeStr)
	var cleaned strings.Builder
	for _, r := range sizeStr {
		if r >= '0' && r <= '9' {
			cleaned.WriteRune(r)
		}
	}

	// Parse number
	cleanedStr := cleaned.String()
	if cleanedStr == "" {
		return 0
	}

	var size int64
	_, err := fmt.Sscanf(cleanedStr, "%d", &size)
	if err != nil {
		return 0
	}

	// Convert bytes to GB
	return float64(size) / (1024 * 1024 * 1024)
}

func formatByteString(sizeStr string) string {
	// Format byte string for display
	sizeGB := parseByteSize(sizeStr)
	if sizeGB >= 1 {
		return fmt.Sprintf("%.2f GB", sizeGB)
	}

	// Convert to MB if less than 1 GB
	sizeMB := sizeGB * 1024
	if sizeMB >= 1 {
		return fmt.Sprintf("%.2f MB", sizeMB)
	}

	// Convert to KB if less than 1 MB
	sizeKB := sizeMB * 1024
	if sizeKB >= 1 {
		return fmt.Sprintf("%.2f KB", sizeKB)
	}

	// Return bytes
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
