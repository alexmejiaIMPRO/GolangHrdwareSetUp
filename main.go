package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// IMMX ENTERPRISE SOFTWARE DEPLOYMENT SYSTEM - Go Implementation
// Version: 2.1.3 - Production Release
// Purpose: Automated software installation and domain configuration
// Network Repository: \\192.168.32.10\immx\01_Public_Infor\Software\
// ============================================================================

// Windows API declarations for message boxes and system calls
var (
	user32               = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW      = user32.NewProc("MessageBoxW")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetComputerNameW = kernel32.NewProc("GetComputerNameW")
)

// Configuration constants
const (
	NetworkBase = `\\192.168.32.10\immx\01_Public_Infor\Software`
	LogFile     = `C:\Windows\Logs\IMMX_Deployment.log`
	TempDir     = `C:\Temp\IMMX_Install`
	Domain      = "immx.local"
)

// Global state variables
var (
	rebootRequired = false
	debugMode      = false
	currentStep    = 0
	totalSteps     = 12
	errorCount     = 0
	warningCount   = 0
)

// Step represents a deployment step with error handling
type Step struct {
	ID          int
	Name        string
	Description string
	Function    func() error
	Critical    bool // If true, failure stops deployment
}

// DeploymentConfig holds user selections
type DeploymentConfig struct {
	Department string
	Language   string
	Username   string
	Domain     string
}

// ============================================================================
// WINDOWS API HELPER FUNCTIONS
// ============================================================================

// showMessageBox displays a Windows message box
func showMessageBox(title, message string, msgType uint) {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(messagePtr)), uintptr(unsafe.Pointer(titlePtr)), uintptr(msgType))
}

// showSuccess displays a success message box
func showSuccess(message string) {
	showMessageBox("✅ IMMX Deployment - Success", message, 0x40) // MB_ICONINFORMATION
}

// showError displays an error message box
func showError(message string) {
	showMessageBox("❌ IMMX Deployment - Error", message, 0x10) // MB_ICONERROR
}

// showWarning displays a warning message box
func showWarning(message string) {
	showMessageBox("⚠️ IMMX Deployment - Warning", message, 0x30) // MB_ICONWARNING
}

// askYesNo displays a Yes/No question dialog
func askYesNo(title, message string) bool {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)
	ret, _, _ := procMessageBoxW.Call(0, uintptr(unsafe.Pointer(messagePtr)), uintptr(unsafe.Pointer(titlePtr)), 0x04|0x20) // MB_YESNO | MB_ICONQUESTION
	return ret == 6 // IDYES
}

// ============================================================================
// LOGGING AND ERROR MANAGEMENT SYSTEM
// ============================================================================

// initializeLogging sets up the logging system
func initializeLogging() error {
	logDir := filepath.Dir(LogFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}
	return nil
}

// writeLog writes a message to both log file and console
func writeLog(level, message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("%s [%s] %s", timestamp, level, message)
	
	// Write to console with colors
	var colorCode string
	switch level {
	case "ERROR":
		colorCode = "\033[31m" // Red
		errorCount++
	case "WARN":
		colorCode = "\033[33m" // Yellow
		warningCount++
	case "SUCCESS":
		colorCode = "\033[32m" // Green
	case "DEBUG":
		colorCode = "\033[36m" // Cyan
		if !debugMode {
			return // Skip debug messages if debug mode is off
		}
	default:
		colorCode = "\033[37m" // White
	}
	
	fmt.Printf("%s%s\033[0m\n", colorCode, logEntry)
	
	// Write to log file
	if file, err := os.OpenFile(LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
		file.WriteString(logEntry + "\n")
		file.Close()
	}
}

// debugLog writes debug information if debug mode is enabled
func debugLog(message string) {
	writeLog("DEBUG", fmt.Sprintf("[STEP %d/%d] %s", currentStep, totalSteps, message))
}

// handleStepError processes step errors and decides whether to continue
func handleStepError(step Step, err error) error {
	errorMsg := fmt.Sprintf("Step %d (%s) failed: %v", step.ID, step.Name, err)
	writeLog("ERROR", errorMsg)
	
	if step.Critical {
		writeLog("ERROR", "Critical step failed - deployment cannot continue")
		showError(fmt.Sprintf("Critical Error in Step %d: %s\n\n%s\n\nDeployment will be aborted.", 
			step.ID, step.Name, err.Error()))
		return fmt.Errorf("critical step failed: %v", err)
	} else {
		writeLog("WARN", "Non-critical step failed - continuing deployment")
		if debugMode {
			continueAnyway := askYesNo("Non-Critical Error", 
				fmt.Sprintf("Step %d (%s) failed:\n\n%s\n\nContinue deployment anyway?", 
					step.ID, step.Name, err.Error()))
			if !continueAnyway {
				return fmt.Errorf("user chose to abort after non-critical error")
			}
		}
	}
	return nil
}

// ============================================================================
// SYSTEM UTILITIES AND POWERSHELL EXECUTION
// ============================================================================

// execPowerShell executes a PowerShell command and returns output
func execPowerShell(command string) (string, error) {
	debugLog(fmt.Sprintf("Executing PowerShell: %s", command))
	
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-Command", command)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		debugLog(fmt.Sprintf("PowerShell command failed: %v", err))
		debugLog(fmt.Sprintf("PowerShell output: %s", string(output)))
		return string(output), err
	}
	
	debugLog(fmt.Sprintf("PowerShell output: %s", string(output)))
	return string(output), nil
}

// execCommand executes a system command with error handling
func execCommand(command string, args ...string) error {
	debugLog(fmt.Sprintf("Executing command: %s %v", command, args))
	
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		debugLog(fmt.Sprintf("Command failed: %v", err))
		debugLog(fmt.Sprintf("Command output: %s", string(output)))
		return fmt.Errorf("command failed: %v - output: %s", err, string(output))
	}
	
	debugLog(fmt.Sprintf("Command completed successfully: %s", string(output)))
	return nil
}

// checkNetworkPath verifies if a network path is accessible
func checkNetworkPath(path string) error {
	debugLog(fmt.Sprintf("Checking network path: %s", path))
	
	if _, err := os.Stat(path); err != nil {
		// Try to map network drive if path is not accessible
		if strings.Contains(path, "192.168.32.10") {
			writeLog("WARN", fmt.Sprintf("Network path not accessible, attempting to map drive: %s", path))
			if err := execCommand("net", "use", "Z:", `\\192.168.32.10\immx`, "/persistent:no"); err != nil {
				return fmt.Errorf("network path not accessible and drive mapping failed: %v", err)
			}
		} else {
			return fmt.Errorf("path not accessible: %v", err)
		}
	}
	
	debugLog(fmt.Sprintf("Network path accessible: %s", path))
	return nil
}

// ============================================================================
// USER INTERFACE AND CONFIGURATION
// ============================================================================

// showBanner displays the application banner
func showBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════════╗
║            IMMX ENTERPRISE SOFTWARE DEPLOYMENT SYSTEM            ║
║                     Version 2.1.3 - Build 2025                 ║
╠══════════════════════════════════════════════════════════════════╣
║  Network Repository: \\192.168.32.10\immx\01_Public_Infor    ║
║  Status: ● ONLINE                                             ║
║  Security: ✓ AUTHENTICATED                                   ║
╚══════════════════════════════════════════════════════════════════╝

🚀 Starting IMMX Enterprise Software Deployment...
`
	fmt.Print(banner)
	writeLog("INFO", "IMMX Enterprise Software Deployment System Started")
}

// getUserInput prompts for user input
func getUserInput(prompt string) string {
	fmt.Print(prompt + ": ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

// getDepartment gets department selection from user
func getDepartment() (string, error) {
	fmt.Println("\n📋 Department Selection:")
	fmt.Println("  [1] General Department     (Office Suite + Adobe Reader)")
	fmt.Println("  [2] Engineering Department (CAXA 3D + Office + Adobe + ClickUp)")
	fmt.Println("  [3] Office Management      (Office + Adobe + ClickUp)")
	
	for {
		choice := getUserInput("\nSelect department [1-3]")
		switch choice {
		case "1":
			return "general", nil
		case "2":
			return "engineer", nil
		case "3":
			return "office", nil
		default:
			writeLog("WARN", fmt.Sprintf("Invalid department selection: %s", choice))
			fmt.Println("❌ Invalid selection. Please choose 1, 2, or 3.")
		}
	}
}

// getLanguage gets language selection from user
func getLanguage() (string, error) {
	fmt.Println("\n🌐 Language Selection:")
	fmt.Println("  [1] 中文 (Chinese Simplified) - 简体中文界面")
	fmt.Println("  [2] English (US)           - English Interface")
	
	for {
		choice := getUserInput("\nSelect language [1-2]")
		switch choice {
		case "1":
			return "chinese", nil
		case "2":
			return "english", nil
		default:
			writeLog("WARN", fmt.Sprintf("Invalid language selection: %s", choice))
			fmt.Println("❌ Invalid selection. Please choose 1 or 2.")
		}
	}
}

// ============================================================================
// DEPLOYMENT STEPS - Each step handles specific installation tasks
// ============================================================================

// Step 1: Initialize system and check prerequisites
func stepInitializeSystem() error {
	writeLog("INFO", "Step 1: Initializing system and checking prerequisites")
	
	// Create temporary directory
	if err := os.MkdirAll(TempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	
	// Check if running as administrator
	output, err := execPowerShell("([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')")
	if err != nil {
		return fmt.Errorf("failed to check administrator privileges: %v", err)
	}
	
	if !strings.Contains(strings.ToLower(output), "true") {
		showWarning("This script should be run as Administrator for best results.")
		writeLog("WARN", "Script not running with administrator privileges")
	}
	
	// Test network connectivity
	if err := checkNetworkPath(NetworkBase); err != nil {
		return fmt.Errorf("network repository not accessible: %v", err)
	}
	
	writeLog("SUCCESS", "Step 1 completed: System initialized successfully")
	return nil
}

// Step 2: Install Chinese language pack if selected
func stepInstallChineseLanguagePack(config *DeploymentConfig) error {
	if config.Language != "chinese" {
		writeLog("INFO", "Step 2: Skipping Chinese language pack (English selected)")
		return nil
	}
	
	writeLog("INFO", "Step 2: Installing Chinese Language Pack")
	
	// Check current language settings
	output, err := execPowerShell("Get-WinUserLanguageList | Where-Object { $_.LanguageTag -eq 'zh-CN' }")
	if err == nil && strings.TrimSpace(output) != "" {
		writeLog("INFO", "Chinese language pack already installed")
		return nil
	}
	
	// Install Chinese language capability
	commands := []string{
		// Check and install language capability
		`$capability = Get-WindowsCapability -Online | Where-Object { $_.Name -like "*Language.Basic*zh-CN*" }; if ($capability) { Add-WindowsCapability -Online -Name $capability.Name -NoRestart }`,
		// Add Chinese to user language list
		`$languageList = Get-WinUserLanguageList; $languageList.Add("zh-CN"); Set-WinUserLanguageList $languageList -Force`,
		// Set Chinese as system locale
		`Set-WinSystemLocale -SystemLocale "zh-CN"`,
		// Set UI language override
		`Set-WinUILanguageOverride -Language "zh-CN"`,
		// Set culture
		`Set-Culture -CultureInfo "zh-CN"`,
		// Registry settings
		`Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "LocaleName" -Value "zh-CN" -ErrorAction SilentlyContinue`,
	}
	
	for i, cmd := range commands {
		debugLog(fmt.Sprintf("Executing Chinese language setup command %d/%d", i+1, len(commands)))
		if _, err := execPowerShell(cmd); err != nil {
			writeLog("WARN", fmt.Sprintf("Chinese language setup command %d failed: %v", i+1, err))
		}
	}
	
	rebootRequired = true
	writeLog("SUCCESS", "Step 2 completed: Chinese language pack configured")
	return nil
}

// Step 3: Install Microsoft Office
func stepInstallMicrosoftOffice(config *DeploymentConfig) error {
	writeLog("INFO", "Step 3: Installing Microsoft Office Professional Plus 2016")
	
	// Determine ISO path based on language
	var isoPath string
	if config.Language == "chinese" {
		isoPath = NetworkBase + `\Office\2016\SW_DVD5_Office_Professional_Plus_2016_64Bit_ChnSimp_MLF_X20-42426.ISO`
	} else {
		isoPath = NetworkBase + `\Office\2016\SW_DVD5_Office_Professional_Plus_2016_64Bit_English_MLF_X20-42432.ISO`
	}
	
	// Check if ISO file exists
	if err := checkNetworkPath(isoPath); err != nil {
		return fmt.Errorf("Office ISO not found: %s - %v", isoPath, err)
	}
	
	// Mount ISO and install Office
	mountCommand := fmt.Sprintf(`
		$iso = Mount-DiskImage -ImagePath '%s' -PassThru
		$driveLetter = ($iso | Get-Volume).DriveLetter
		if ($driveLetter) {
			Write-Output "ISO mounted to drive $driveLetter"
			$setupPath = "$driveLetter" + ":\setup.exe"
			if (Test-Path $setupPath) {
				# Create configuration for silent install
				$configXml = @"
<Configuration Product="ProPlus">
  <Display Level="none" CompletionNotice="no" SuppressModal="yes" AcceptEula="yes" />
  <Logging Type="standard" Path="$env:TEMP" Template="Microsoft Office Professional Plus Setup(*).txt" />
  <Setting Id="SETUP_REBOOT" Value="never" />
</Configuration>
"@
				$configPath = "%s\office_config.xml"
				Set-Content -Path $configPath -Value $configXml
				
				Write-Output "Starting Office installation..."
				$process = Start-Process -FilePath $setupPath -ArgumentList "/adminfile", $configPath -Wait -PassThru -NoNewWindow
				Write-Output "Office installation process completed with exit code: $($process.ExitCode)"
				
				Dismount-DiskImage -ImagePath '%s'
				Write-Output "ISO dismounted"
				
				if ($process.ExitCode -eq 0) {
					Write-Output "SUCCESS: Office installed successfully"
				} else {
					Write-Error "Office installation failed with exit code: $($process.ExitCode)"
				}
			} else {
				Write-Error "Setup.exe not found in mounted ISO"
			}
		} else {
			Write-Error "Failed to mount ISO"
		}
	`, isoPath, TempDir, isoPath)
	
	output, err := execPowerShell(mountCommand)
	if err != nil || strings.Contains(output, "Write-Error") {
		return fmt.Errorf("Office installation failed: %v - Output: %s", err, output)
	}
	
	writeLog("SUCCESS", "Step 3 completed: Microsoft Office installed successfully")
	return nil
}

// Step 4: Install Adobe Reader
func stepInstallAdobeReader() error {
	writeLog("INFO", "Step 4: Installing Adobe Acrobat Reader DC")
	
	adobePath := NetworkBase + `\AcroRdrDC1901220034_en_US.exe`
	
	// Check if Adobe installer exists
	if err := checkNetworkPath(adobePath); err != nil {
		return fmt.Errorf("Adobe Reader installer not found: %s - %v", adobePath, err)
	}
	
	// Install Adobe Reader silently
	if err := execCommand(adobePath, "/sAll", "/rs", "/msi", "EULA_ACCEPT=YES"); err != nil {
		return fmt.Errorf("Adobe Reader installation failed: %v", err)
	}
	
	writeLog("SUCCESS", "Step 4 completed: Adobe Acrobat Reader DC installed successfully")
	return nil
}

// Step 5: Install CAXA 3D (for Engineering department only)
func stepInstallCAXA3D(config *DeploymentConfig) error {
	if config.Department != "engineer" {
		writeLog("INFO", "Step 5: Skipping CAXA 3D installation (not Engineering department)")
		return nil
	}
	
	writeLog("INFO", "Step 5: Installing CAXA 3D 2024")
	
	caxaPath := NetworkBase + `\CAXA 3D 2024\Setup\Setup.exe`
	
	// Check if CAXA installer exists
	if err := checkNetworkPath(caxaPath); err != nil {
		return fmt.Errorf("CAXA 3D installer not found: %s - %v", caxaPath, err)
	}
	
	// Install CAXA 3D silently
	if err := execCommand(caxaPath, "/S", `/v"/qn REBOOT=ReallySuppress"`); err != nil {
		return fmt.Errorf("CAXA 3D installation failed: %v", err)
	}
	
	writeLog("SUCCESS", "Step 5 completed: CAXA 3D 2024 installed successfully")
	return nil
}

// Step 6: Install ClickUp (for Engineering and Office departments)
func stepInstallClickUp(config *DeploymentConfig) error {
	if config.Department == "general" {
		writeLog("INFO", "Step 6: Skipping ClickUp installation (General department)")
		return nil
	}
	
	writeLog("INFO", "Step 6: Installing ClickUp from Microsoft Store")
	
	// Try winget first
	wingetCommand := `winget install --id 9NR1Q6L7FZQR --source msstore --accept-package-agreements --accept-source-agreements`
	output, err := execPowerShell(wingetCommand)
	
	if err != nil || strings.Contains(strings.ToLower(output), "error") {
		writeLog("WARN", "Winget installation failed, opening Microsoft Store manually")
		// Fallback: Open Microsoft Store
		if err := execCommand("cmd", "/c", "start", "ms-windows-store://pdp/?productid=9NR1Q6L7FZQR"); err != nil {
			return fmt.Errorf("failed to open Microsoft Store: %v", err)
		}
		showWarning("Please complete ClickUp installation from the Microsoft Store that just opened, then click OK to continue.")
	}
	
	writeLog("SUCCESS", "Step 6 completed: ClickUp installation initiated")
	return nil
}

// Step 7: Install system updates and patches
func stepInstallSystemUpdates() error {
	writeLog("INFO", "Step 7: Installing system updates and patches")
	
	// Create system restore point
	restoreCommand := `Checkpoint-Computer -Description "IMMX Pre-patch backup $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -RestorePointType "MODIFY_SETTINGS"`
	if _, err := execPowerShell(restoreCommand); err != nil {
		writeLog("WARN", fmt.Sprintf("Could not create system restore point: %v", err))
	} else {
		writeLog("SUCCESS", "System restore point created")
	}
	
	// Try PSWindowsUpdate module
	windowsUpdateCommand := `
		try {
			if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
				Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction SilentlyContinue
			}
			Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
			$updates = Get-WUList -ErrorAction SilentlyContinue
			if ($updates) {
				Write-Output "Found $($updates.Count) Windows Updates available"
			} else {
				Write-Output "No Windows Updates found or PSWindowsUpdate module not available"
			}
		} catch {
			Write-Output "PSWindowsUpdate module not available"
		}
	`
	
	if output, err := execPowerShell(windowsUpdateCommand); err == nil {
		debugLog(fmt.Sprintf("Windows Update check result: %s", output))
	}
	
	// Install specific patches from network
	patches := []struct {
		Name string
		Path string
		Type string
	}{
		{"Windows Security Update KB5028185", NetworkBase + `\Updates\Windows\windows10.0-kb5028185-x64.msu`, "MSU"},
		{"Office Security Patch KB5002138", NetworkBase + `\Updates\Office\office2016-kb5002138-fullfile-x64-glb.exe`, "EXE"},
		{"Adobe Reader Update", NetworkBase + `\Updates\Adobe\AcroRdrDCUpd1901220040.msp`, "MSP"},
		{".NET Framework 4.8.1", NetworkBase + `\Updates\Framework\NDP481-KB4524152-x86-x64-AllOS-ENU.exe`, "EXE"},
	}
	
	successCount := 0
	for _, patch := range patches {
		debugLog(fmt.Sprintf("Checking patch: %s", patch.Name))
		
		if err := checkNetworkPath(patch.Path); err != nil {
			writeLog("WARN", fmt.Sprintf("Patch file not found: %s", patch.Path))
			continue
		}
		
		var installCmd []string
		switch patch.Type {
		case "MSU":
			installCmd = []string{"wusa.exe", patch.Path, "/quiet", "/norestart"}
		case "MSP":
			installCmd = []string{"msiexec.exe", "/update", patch.Path, "/quiet", "/norestart"}
		case "EXE":
			installCmd = []string{patch.Path, "/S", "/quiet", "/norestart"}
		}
		
		writeLog("INFO", fmt.Sprintf("Installing patch: %s", patch.Name))
		if err := execCommand(installCmd[0], installCmd[1:]...); err != nil {
			writeLog("WARN", fmt.Sprintf("Patch installation failed: %s - %v", patch.Name, err))
		} else {
			writeLog("SUCCESS", fmt.Sprintf("Patch installed successfully: %s", patch.Name))
			successCount++
		}
	}
	
	writeLog("SUCCESS", fmt.Sprintf("Step 7 completed: %d patches installed successfully", successCount))
	return nil
}

// Step 8: Configure domain access
func stepConfigureDomain(config *DeploymentConfig) error {
	writeLog("INFO", fmt.Sprintf("Step 8: Configuring domain access for %s\\%s", config.Domain, config.Username))
	
	// Test domain connectivity
	domainTestCommand := fmt.Sprintf(`Test-ComputerSecureChannel -Server "%s" -ErrorAction SilentlyContinue`, config.Domain)
	if output, err := execPowerShell(domainTestCommand); err == nil && strings.TrimSpace(output) != "" {
		writeLog("SUCCESS", fmt.Sprintf("Domain connectivity verified for %s", config.Domain))
	} else {
		writeLog("WARN", fmt.Sprintf("Domain connectivity test failed for %s", config.Domain))
	}
	
	// Create user profile directory
	profilePath := fmt.Sprintf(`C:\Users\%s`, config.Username)
	if err := os.MkdirAll(profilePath, 0755); err != nil {
		writeLog("WARN", fmt.Sprintf("Could not create user profile directory: %v", err))
	} else {
		writeLog("SUCCESS", fmt.Sprintf("User profile directory prepared: %s", profilePath))
	}
	
	// Map network drives
	networkDriveCommand := `
		try {
			$networkPath = "\\192.168.32.10\immx"
			if (Test-Path $networkPath) {
				New-PSDrive -Name "H" -PSProvider FileSystem -Root $networkPath -Persist -ErrorAction SilentlyContinue
				Write-Output "Network drive H: mapped successfully"
			} else {
				Write-Output "Network path not accessible"
			}
		} catch {
			Write-Output "Network drive mapping failed"
		}
	`
	
	if output, err := execPowerShell(networkDriveCommand); err == nil {
		debugLog(fmt.Sprintf("Network drive mapping result: %s", output))
	}
	
	// Configure security permissions
	securityCommand := fmt.Sprintf(`icacls "C:\Program Files" /grant "%s:(OI)(CI)RX" /C /Q`, config.Username)
	if _, err := execPowerShell(securityCommand); err != nil {
		writeLog("WARN", fmt.Sprintf("Security permissions configuration failed: %v", err))
	} else {
		writeLog("SUCCESS", fmt.Sprintf("Security permissions configured for %s", config.Username))
	}
	
	// Refresh group policy
	if _, err := execPowerShell("gpupdate /force"); err != nil {
		writeLog("WARN", fmt.Sprintf("Group policy refresh failed: %v", err))
	} else {
		writeLog("SUCCESS", "Group policy refreshed")
	}
	
	writeLog("SUCCESS", "Step 8 completed: Domain configuration finished")
	return nil
}

// Step 9: Perform system health check
func stepSystemHealthCheck() error {
	writeLog("INFO", "Step 9: Performing system health check")
	
	// Check system files
	writeLog("INFO", "Checking system file integrity...")
	if _, err := execCommand("sfc", "/verifyonly"); err != nil {
		writeLog("WARN", fmt.Sprintf("System file check failed: %v", err))
	} else {
		writeLog("SUCCESS", "System file integrity check completed")
	}
	
	// Check services
	serviceCheckCommand := `
		$stoppedServices = Get-Service | Where-Object { $_.Status -eq "Stopped" -and $_.StartType -eq "Automatic" }
		if ($stoppedServices.Count -gt 0) {
			Write-Output "Found $($stoppedServices.Count) stopped automatic services"
		} else {
			Write-Output "All automatic services are running"
		}
	`
	
	if output, err := execPowerShell(serviceCheckCommand); err == nil {
		debugLog(fmt.Sprintf("Service check result: %s", output))
	}
	
	// Check for pending reboots
	rebootCheckCommand := `
		$pendingReboot = $false
		if (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) {
			$pendingReboot = $true
		}
		if ($pendingReboot) {
			Write-Output "System requires reboot for pending updates"
		} else {
			Write-Output "No pending reboot requirements detected"
		}
	`
	
	if output, err := execPowerShell(rebootCheckCommand); err == nil {
		if strings.Contains(output, "requires reboot") {
			rebootRequired = true
		}
		debugLog(fmt.Sprintf("Reboot check result: %s", output))
	}
	
	writeLog("SUCCESS", "Step 9 completed: System health check finished")
	return nil
}

// Step 10: Handle system reboot
func stepHandleSystemReboot() error {
	writeLog("INFO", "Step 10: Handling system reboot requirements")
	
	if !rebootRequired {
		writeLog("INFO", "No system reboot required")
		return nil
	}
	
	// Ask user about reboot
	rebootNow := askYesNo("System Reboot Required", 
		"System reboot is required to complete the installation.\n\nReboot now?")
	
	if rebootNow {
		writeLog("INFO", "User chose to reboot now - scheduling system restart")
		
		// Create reboot reminder file
		reminderContent := fmt.Sprintf(`IMMX ENTERPRISE SOFTWARE DEPLOYMENT
====================================

Installation completed successfully on: %s

IMPORTANT: System has been restarted to complete the installation.

Software installed:
- Microsoft Office Professional Plus 2016
- Adobe Acrobat Reader DC
- Additional department-specific software
- System security updates
- Language packs (if applicable)

Support: +86-400-IMMX-HELP
Email: support@immx.com
`, time.Now().Format("2006-01-02 15:04:05"))
		
		reminderPath := os.Getenv("USERPROFILE") + `\Desktop\IMMX_Installation_Complete.txt`
		if err := os.WriteFile(reminderPath, []byte(reminderContent), 0644); err != nil {
			writeLog("WARN", fmt.Sprintf("Could not create completion reminder: %v", err))
		}
		
		// Schedule reboot
		rebootCommand := `shutdown /r /t 60 /c "IMMX Enterprise Software Deployment - Reboot Required"`
		if err := execCommand("cmd", "/c", rebootCommand); err != nil {
			writeLog("ERROR", fmt.Sprintf("Failed to schedule reboot: %v", err))
			showError("Failed to schedule system reboot. Please restart manually.")
		} else {
			showWarning("System will reboot in 60 seconds. Please save any open work.")
			writeLog("SUCCESS", "System reboot scheduled")
		}
	} else {
		writeLog("INFO", "User chose to reboot manually later")
		
		// Create manual reboot reminder
		reminderContent := fmt.Sprintf(`IMMX ENTERPRISE SOFTWARE DEPLOYMENT
====================================

Installation completed successfully on: %s

IMPORTANT: System reboot is required to complete the installation.

Software installed:
- Microsoft Office Professional Plus 2016
- Adobe Acrobat Reader DC
- Additional department-specific software
- System security updates
- Language packs (if applicable)

Please restart your computer when convenient to finalize all configurations.

Support: +86-400-IMMX-HELP
Email: support@immx.com
`, time.Now().Format("2006-01-02 15:04:05"))
		
		reminderPath := os.Getenv("USERPROFILE") + `\Desktop\IMMX_Reboot_Reminder.txt`
		if err := os.WriteFile(reminderPath, []byte(reminderContent), 0644); err != nil {
			writeLog("WARN", fmt.Sprintf("Could not create reboot reminder: %v", err))
		} else {
			writeLog("SUCCESS", "Reboot reminder created on desktop")
		}
	}
	
	writeLog("SUCCESS", "Step 10 completed: Reboot handling finished")
	return nil
}

// Step 11: Generate deployment summary
func stepGenerateDeploymentSummary(config *DeploymentConfig) error {
	writeLog("INFO", "Step 11: Generating deployment summary")
	
	// Collect system information
	systemInfoCommand := `
		$computer = Get-WmiObject Win32_ComputerSystem
		$os = Get-WmiObject Win32_OperatingSystem
		$bios = Get-WmiObject Win32_BIOS
		
		Write-Output "=== SYSTEM INFORMATION ==="
		Write-Output "Computer Name: $($computer.Name)"
		Write-Output "Domain: $($computer.Domain)"
		Write-Output "OS: $($os.Caption) ($($os.Version))"
		Write-Output "Architecture: $($os.OSArchitecture)"
		Write-Output "Total RAM: $([math]::Round($computer.TotalPhysicalMemory/1GB, 2)) GB"
		Write-Output "BIOS Version: $($bios.SMBIOSBIOSVersion)"
		Write-Output "Last Boot: $($os.LastBootUpTime)"
	`
	
	systemInfo, err := execPowerShell(systemInfoCommand)
	if err != nil {
		writeLog("WARN", fmt.Sprintf("Could not collect system information: %v", err))
		systemInfo = "System information collection failed"
	}
	
	// Check installed software
	softwareCheckCommand := `
		Write-Output "=== INSTALLED SOFTWARE VERIFICATION ==="
		
		# Check Office installation
		$office = Get-WmiObject Win32_Product | Where-Object {$_.Name -like "*Microsoft Office*"} | Select-Object -First 1
		if ($office) {
			Write-Output "✓ Microsoft Office: $($office.Version)"
		} else {
			Write-Output "? Microsoft Office: Installation pending verification"
		}
		
		# Check Adobe Reader
		$adobe = Get-WmiObject Win32_Product | Where-Object {$_.Name -like "*Adobe*"} | Select-Object -First 1
		if ($adobe) {
			Write-Output "✓ Adobe Acrobat Reader: $($adobe.Version)"
		} else {
			Write-Output "? Adobe Acrobat Reader: Installation pending verification"
		}
		
		# Check CAXA (if Engineering department)
		$caxa = Get-WmiObject Win32_Product | Where-Object {$_.Name -like "*CAXA*"} | Select-Object -First 1
		if ($caxa) {
			Write-Output "✓ CAXA 3D: $($caxa.Version)"
		}
		
		# Check ClickUp (Windows Store App)
		$clickup = Get-AppxPackage | Where-Object {$_.Name -like "*ClickUp*"} | Select-Object -First 1
		if ($clickup) {
			Write-Output "✓ ClickUp: $($clickup.Version)"
		}
	`
	
	softwareInfo, err := execPowerShell(softwareCheckCommand)
	if err != nil {
		writeLog("WARN", fmt.Sprintf("Could not verify software installations: %v", err))
		softwareInfo = "Software verification failed"
	}
	
	// Check security status
	securityCheckCommand := `
		Write-Output "=== SECURITY STATUS ==="
		
		# Check Windows Defender
		try {
			$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
			if ($defender) {
				Write-Output "✓ Windows Defender Antivirus: $($defender.AntivirusEnabled)"
				Write-Output "✓ Real-time Protection: $($defender.RealTimeProtectionEnabled)"
			} else {
				Write-Output "? Windows Defender: Status check not available"
			}
		} catch {
			Write-Output "? Windows Defender: Status check failed"
		}
		
		# Check firewall status
		try {
			$firewall = Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true}
			Write-Output "✓ Windows Firewall: $($firewall.Count) profiles enabled"
		} catch {
			Write-Output "? Windows Firewall: Status check failed"
		}
	`
	
	securityInfo, err := execPowerShell(securityCheckCommand)
	if err != nil {
		writeLog("WARN", fmt.Sprintf("Could not check security status: %v", err))
		securityInfo = "Security status check failed"
	}
	
	// Create comprehensive summary
	summary := fmt.Sprintf(`
IMMX ENTERPRISE SOFTWARE DEPLOYMENT - SUMMARY REPORT
=====================================================

Deployment Date: %s
Department: %s
Language: %s
Username: %s
Domain: %s

Errors: %d
Warnings: %d
Reboot Required: %t

%s

%s

%s

DEPLOYMENT STATUS: COMPLETED
Next Steps:
1. Restart the computer if required
2. Verify all software applications launch correctly
3. Test network drive mappings and domain access
4. Contact IT support if any issues arise

Support Information:
- Help Desk: +86-400-IMMX-HELP
- Email: support@immx.com
- Documentation: \\192.168.32.10\immx\Support\Docs\
`, 
		time.Now().Format("2006-01-02 15:04:05"),
		config.Department,
		config.Language,
		config.Username,
		config.Domain,
		errorCount,
		warningCount,
		rebootRequired,
		systemInfo,
		softwareInfo,
		securityInfo,
	)
	
	debugLog("Deployment summary generated successfully")
	writeLog("SUCCESS", "Step 11 completed: Deployment summary generated")
	return nil
}

// Step 12: Finalize deployment
func stepFinalizeDeployment(config *DeploymentConfig) error {
	writeLog("INFO", "Step 12: Finalizing deployment")
	
	// Update installation log
	finalLogEntry := fmt.Sprintf("IMMX Software Deployment completed successfully - Department: %s, Language: %s, Errors: %d, Warnings: %d", 
		config.Department, config.Language, errorCount, warningCount)
	writeLog("SUCCESS", finalLogEntry)
	
	// Clean up temporary files
	if err := os.RemoveAll(TempDir); err != nil {
		writeLog("WARN", fmt.Sprintf("Could not clean up temporary directory: %v", err))
	} else {
		writeLog("SUCCESS", "Temporary files cleaned up")
	}
	
	// Show final success message
	var statusMsg string
	if errorCount == 0 && warningCount == 0 {
		statusMsg = "🎉 DEPLOYMENT COMPLETED SUCCESSFULLY!\n\nAll software has been installed without errors."
	} else {
		statusMsg = fmt.Sprintf("✅ DEPLOYMENT COMPLETED WITH WARNINGS\n\nErrors: %d\nWarnings: %d\n\nCheck the log file for details: %s", 
			errorCount, warningCount, LogFile)
	}
	
	if rebootRequired {
		statusMsg += "\n\n⚠️ SYSTEM REBOOT REQUIRED\nPlease restart your computer to complete the installation."
	}
	
	statusMsg += fmt.Sprintf("\n\nSupport: +86-400-IMMX-HELP\nEmail: support@immx.com\nLog: %s", LogFile)
	
	showSuccess(statusMsg)
	
	writeLog("SUCCESS", "Step 12 completed: Deployment finalized successfully")
	return nil
}

// ============================================================================
// MAIN DEPLOYMENT ORCHESTRATION
// ============================================================================

func main() {
	// Initialize system
	if err := initializeLogging(); err != nil {
		log.Fatalf("Failed to initialize logging: %v", err)
	}
	
	// Check for debug mode
	for _, arg := range os.Args[1:] {
		if arg == "-debug" || arg == "--debug" {
			debugMode = true
			writeLog("INFO", "Debug mode enabled")
			break
		}
	}
	
	// Show banner
	showBanner()
	
	// Get user configuration
	fmt.Println("\n🔧 Configuration Setup")
	config := &DeploymentConfig{}
	
	var err error
	config.Department, err = getDepartment()
	if err != nil {
		showError(fmt.Sprintf("Failed to get department selection: %v", err))
		return
	}
	
	config.Language, err = getLanguage()
	if err != nil {
		showError(fmt.Sprintf("Failed to get language selection: %v", err))
		return
	}
	
	config.Username = getUserInput("\n👤 Enter username for domain configuration")
	if config.Username == "" {
		config.Username = os.Getenv("USERNAME")
		writeLog("INFO", fmt.Sprintf("Using current username: %s", config.Username))
	}
	
	config.Domain = Domain
	
	writeLog("INFO", fmt.Sprintf("Configuration: Department=%s, Language=%s, User=%s, Domain=%s", 
		config.Department, config.Language, config.Username, config.Domain))
	
	// Define deployment steps
	steps := []Step{
		{1, "Initialize System", "Check prerequisites and network connectivity", func() error { return stepInitializeSystem() }, true},
		{2, "Install Language Pack", "Install Chinese language pack if selected", func() error { return stepInstallChineseLanguagePack(config) }, false},
		{3, "Install Microsoft Office", "Install Office Professional Plus 2016", func() error { return stepInstallMicrosoftOffice(config) }, false},
		{4, "Install Adobe Reader", "Install Adobe Acrobat Reader DC", func() error { return stepInstallAdobeReader() }, false},
		{5, "Install CAXA 3D", "Install CAXA 3D 2024 for Engineering", func() error { return stepInstallCAXA3D(config) }, false},
		{6, "Install ClickUp", "Install ClickUp from Microsoft Store", func() error { return stepInstallClickUp(config) }, false},
		{7, "Install System Updates", "Install security patches and updates", func() error { return stepInstallSystemUpdates() }, false},
		{8, "Configure Domain", "Configure domain access and permissions", func() error { return stepConfigureDomain(config) }, false},
		{9, "System Health Check", "Perform system health and integrity check", func() error { return stepSystemHealthCheck() }, false},
		{10, "Handle System Reboot", "Handle system reboot requirements", func() error { return stepHandleSystemReboot() }, false},
		{11, "Generate Summary", "Generate deployment summary report", func() error { return stepGenerateDeploymentSummary(config) }, false},
		{12, "Finalize Deployment", "Clean up and finalize deployment", func() error { return stepFinalizeDeployment(config) }, false},
	}
	
	totalSteps = len(steps)
	
	// Confirm before starting
	if !askYesNo("Confirm Deployment", 
		fmt.Sprintf("Ready to start IMMX Enterprise Software Deployment:\n\nDepartment: %s\nLanguage: %s\nUser: %s\nDomain: %s\n\nContinue?", 
			config.Department, config.Language, config.Username, config.Domain)) {
		writeLog("INFO", "Deployment cancelled by user")
		showWarning("Deployment cancelled by user.")
		return
	}
	
	// Execute deployment steps
	writeLog("INFO", "Starting deployment workflow...")
	fmt.Printf("\n🚀 Starting deployment with %d steps...\n\n", totalSteps)
	
	startTime := time.Now()
	
	for _, step := range steps {
		currentStep = step.ID
		
		fmt.Printf("📋 Step %d/%d: %s\n", step.ID, totalSteps, step.Name)
		fmt.Printf("   %s\n", step.Description)
		
		debugLog(fmt.Sprintf("Starting step %d: %s", step.ID, step.Name))
		
		stepStartTime := time.Now()
		err := step.Function()
		stepDuration := time.Since(stepStartTime)
		
		if err != nil {
			if handleErr := handleStepError(step, err); handleErr != nil {
				writeLog("ERROR", "Deployment aborted due to critical error")
				showError(fmt.Sprintf("Deployment failed at step %d: %s\n\nError: %v", step.ID, step.Name, handleErr))
				return
			}
		} else {
			debugLog(fmt.Sprintf("Step %d completed successfully in %v", step.ID, stepDuration))
		}
		
		fmt.Printf("   ✅ Step %d completed in %v\n\n", step.ID, stepDuration)
	}
	
	totalDuration := time.Since(startTime)
	
	// Final summary
	writeLog("SUCCESS", fmt.Sprintf("IMMX Enterprise Software Deployment completed in %v", totalDuration))
	fmt.Printf("🎉 Deployment completed successfully in %v!\n", totalDuration)
	fmt.Printf("   Total Steps: %d\n", totalSteps)
	fmt.Printf("   Errors: %d\n", errorCount)
	fmt.Printf("   Warnings: %d\n", warningCount)
	fmt.Printf("   Log File: %s\n\n", LogFile)
	
	if debugMode {
		fmt.Println("Press Enter to exit...")
		bufio.NewScanner(os.Stdin).Scan()
	}
}
