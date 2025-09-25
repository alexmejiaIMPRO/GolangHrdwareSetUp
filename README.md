# IMMX Enterprise Software Deployment System

## 📋 Overview

The IMMX Enterprise Software Deployment System is a comprehensive Go-based automation tool designed for enterprise software installation and domain configuration. It provides a professional, step-by-step deployment process with advanced error handling and Windows-native user interface integration.

### 🎯 Purpose
- Automated installation of department-specific software packages
- Chinese/English language pack configuration
- Domain user setup and network drive mapping
- System security updates and patch management
- Professional error handling and logging

### 🏢 Target Environment
- **Network Repository**: `\\192.168.32.10\immx\01_Public_Infor\Software\`
- **Domain**: `immx.local`
- **Operating System**: Windows 10/11 Enterprise
- **Requirements**: Administrator privileges recommended

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────┐
│           Main Orchestrator             │
├─────────────────────────────────────────┤
│  • User Interface Management            │
│  • Step Execution Controller            │
│  • Error Handling Coordinator           │
└─────────────────┬───────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
┌───▼───┐   ┌────▼────┐   ┌───▼────┐
│Windows│   │PowerShell│   │Network │
│  API  │   │Execution │   │Access  │
│Layer  │   │ Engine   │   │Manager │
└───────┘   └─────────┘   └────────┘
```

---

## 📚 Core Components

### 1. **Windows API Integration**

#### `user32.dll` and `kernel32.dll` Bindings
```go
var (
    user32               = syscall.NewLazyDLL("user32.dll")
    procMessageBoxW      = user32.NewProc("MessageBoxW")
    kernel32             = syscall.NewLazyDLL("kernel32.dll")
    procGetComputerNameW = kernel32.NewProc("GetComputerNameW")
)
```
**Purpose**: Provides native Windows dialog boxes and system information access.

#### Message Box Functions
- **`showMessageBox(title, message, msgType)`**: Core Windows MessageBox wrapper
- **`showSuccess(message)`**: Green checkmark success dialogs
- **`showError(message)`**: Red X error dialogs  
- **`showWarning(message)`**: Yellow warning dialogs
- **`askYesNo(title, message)`**: Interactive Yes/No prompts

**Usage Example**:
```go
showSuccess("Installation completed successfully!")
if askYesNo("Reboot Required", "Restart now?") {
    // Handle reboot
}
```

---

### 2. **Configuration Management**

#### Global Constants
```go
const (
    NetworkBase = `\\192.168.32.10\immx\01_Public_Infor\Software`
    LogFile     = `C:\Windows\Logs\IMMX_Deployment.log`
    TempDir     = `C:\Temp\IMMX_Install`
    Domain      = "immx.local"
)
```

#### State Variables
```go
var (
    rebootRequired = false  // Tracks if system restart needed
    debugMode      = false  // Enables detailed logging
    currentStep    = 0      // Current deployment step
    totalSteps     = 12     // Total deployment steps
    errorCount     = 0      // Critical error counter
    warningCount   = 0      // Warning counter
)
```

#### Data Structures
```go
type Step struct {
    ID          int         // Step number (1-12)
    Name        string      // Display name
    Description string      // Detailed description
    Function    func() error // Execution function
    Critical    bool        // Stops deployment if fails
}

type DeploymentConfig struct {
    Department string // "general", "engineer", "office"
    Language   string // "chinese", "english"  
    Username   string // Domain username
    Domain     string // Domain name (immx.local)
}
```

---

### 3. **Logging and Error Management System**

#### Logging Functions

**`initializeLogging()`**
- Creates log directory structure
- Sets up file permissions
- Returns error if cannot create log directory

**`writeLog(level, message)`**
- **Parameters**: 
  - `level`: "ERROR", "WARN", "SUCCESS", "INFO", "DEBUG"
  - `message`: Log message content
- **Features**:
  - Console output with color coding
  - File logging with timestamps
  - Error/warning counters
- **Example**:
```go
writeLog("SUCCESS", "Office installation completed")
writeLog("ERROR", "Network path not accessible")
```

**`debugLog(message)`**
- Only outputs when `debugMode = true`
- Includes step progression information
- Prefixes with `[STEP X/Y]` format

**`handleStepError(step, err)`**
- **Critical Steps**: Shows error dialog, aborts deployment
- **Non-Critical Steps**: Shows warning, continues deployment
- **Debug Mode**: Asks user whether to continue
- Updates error counters automatically

---

### 4. **PowerShell and Command Execution**

#### PowerShell Interface

**`execPowerShell(command)`**
```go
func execPowerShell(command string) (string, error) {
    cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-Command", command)
    output, err := cmd.CombinedOutput()
    // Error handling and debug logging
    return string(output), err
}
```
- **Purpose**: Execute PowerShell scripts with bypass policy
- **Features**: Debug logging, error capture, output parsing
- **Usage**: Windows-specific operations, WMI queries, system configuration

**`execCommand(command, args...)`**
```go
func execCommand(command string, args ...string) error {
    cmd := exec.Command(command, args...)
    output, err := cmd.CombinedOutput()
    // Debug logging and error handling
    return err
}
```
- **Purpose**: Execute system commands (CMD, executables)
- **Features**: Argument handling, output capture, debug integration

#### Network Path Management

**`checkNetworkPath(path)`**
- Verifies network share accessibility
- Attempts automatic drive mapping if path fails
- Uses `net use` command for UNC path mapping
- Returns detailed error information

---

### 5. **User Interface System**

#### Console Interface

**`showBanner()`**
- Displays professional ASCII art header
- Shows system information and status
- Initializes logging system

**`getUserInput(prompt)`**
- Standard console input with prompt
- Handles string trimming and validation
- Used for configuration collection

#### Configuration Collection

**`getDepartment()`**
- Interactive menu system (1-3 options)
- Input validation with retry logic
- Returns: "general", "engineer", "office"
- **Software Packages**:
  - **General**: Office + Adobe Reader
  - **Engineer**: CAXA + Office + Adobe + ClickUp
  - **Office**: Office + Adobe + ClickUp

**`getLanguage()`** 
- Bilingual interface (Chinese/English)
- Determines software language versions
- Returns: "chinese", "english"
- **Impact**: 
  - Office ISO selection (Chinese vs English)
  - Language pack installation trigger

---

## 🔧 Deployment Steps (Detailed Breakdown)

### Step 1: Initialize System
**Function**: `stepInitializeSystem()`

**Purpose**: System readiness verification and setup

**Operations**:
1. **Directory Creation**: Creates `C:\Temp\IMMX_Install`
2. **Admin Check**: Verifies administrator privileges
   ```powershell
   ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
   ```
3. **Network Test**: Validates repository accessibility
4. **Drive Mapping**: Maps network share if needed

**Critical**: Yes (deployment stops if network unavailable)

**Error Handling**:
- Directory creation failure → Abort
- Network unavailable → Attempt drive mapping → Abort if fails
- Non-admin privileges → Warning only

---

### Step 2: Install Chinese Language Pack
**Function**: `stepInstallChineseLanguagePack(config)`

**Purpose**: Windows Chinese language configuration

**Conditional**: Only runs if `config.Language == "chinese"`

**Operations**:
1. **Current Language Check**: 
   ```powershell
   Get-WinUserLanguageList | Where-Object { $_.LanguageTag -eq 'zh-CN' }
   ```
2. **Language Capability Installation**:
   ```powershell
   $capability = Get-WindowsCapability -Online | Where-Object { $_.Name -like "*Language.Basic*zh-CN*" }
   Add-WindowsCapability -Online -Name $capability.Name -NoRestart
   ```
3. **User Language List Update**:
   ```powershell
   $languageList = Get-WinUserLanguageList
   $languageList.Add("zh-CN")
   Set-WinUserLanguageList $languageList -Force
   ```
4. **System Locale Configuration**:
   ```powershell
   Set-WinSystemLocale -SystemLocale "zh-CN"
   Set-WinUILanguageOverride -Language "zh-CN"  
   Set-Culture -CultureInfo "zh-CN"
   ```
5. **Registry Configuration**: Updates International Control Panel settings

**Side Effects**: Sets `rebootRequired = true`

**Error Handling**: Non-critical (warnings only, continues deployment)

---

### Step 3: Install Microsoft Office
**Function**: `stepInstallMicrosoftOffice(config)`

**Purpose**: Office Professional Plus 2016 installation

**Network Paths**:
- **Chinese**: `SW_DVD5_Office_Professional_Plus_2016_64Bit_ChnSimp_MLF_X20-42426.ISO`
- **English**: `SW_DVD5_Office_Professional_Plus_2016_64Bit_English_MLF_X20-42432.ISO`

**Operations**:
1. **Path Selection**: Based on language configuration
2. **File Verification**: Checks ISO accessibility
3. **ISO Mounting**:
   ```powershell
   $iso = Mount-DiskImage -ImagePath 'path' -PassThru
   $driveLetter = ($iso | Get-Volume).DriveLetter
   ```
4. **Configuration XML Creation**:
   ```xml
   <Configuration Product="ProPlus">
     <Display Level="none" CompletionNotice="no" SuppressModal="yes" AcceptEula="yes" />
     <Setting Id="SETUP_REBOOT" Value="never" />
   </Configuration>
   ```
5. **Silent Installation**:
   ```powershell
   Start-Process -FilePath setup.exe -ArgumentList "/adminfile", $configPath -Wait -PassThru
   ```
6. **ISO Dismounting**: Cleanup mounted image

**Error Handling**: Non-critical (Office failure doesn't stop other software)

---

### Step 4: Install Adobe Reader
**Function**: `stepInstallAdobeReader()`

**Purpose**: Adobe Acrobat Reader DC installation

**Network Path**: `AcroRdrDC1901220034_en_US.exe`

**Operations**:
1. **File Verification**: Checks installer accessibility  
2. **Silent Installation**:
   ```cmd
   AcroRdrDC1901220034_en_US.exe /sAll /rs /msi EULA_ACCEPT=YES
   ```

**Parameters Explained**:
- `/sAll`: Silent installation
- `/rs`: Suppress restart
- `/msi`: MSI mode
- `EULA_ACCEPT=YES`: Auto-accept license

**Error Handling**: Non-critical

---

### Step 5: Install CAXA 3D
**Function**: `stepInstallCAXA3D(config)`

**Purpose**: CAXA 3D 2024 CAD software installation

**Conditional**: Only runs if `config.Department == "engineer"`

**Network Path**: `CAXA 3D 2024\Setup\Setup.exe`

**Operations**:
1. **Department Check**: Skip if not Engineering
2. **File Verification**: Checks installer path
3. **Silent Installation**:
   ```cmd
   Setup.exe /S /v"/qn REBOOT=ReallySuppress"
   ```

**Parameters Explained**:
- `/S`: Silent mode
- `/v`: Pass arguments to MSI
- `/qn`: No UI
- `REBOOT=ReallySuppress`: Prevent automatic reboot

**Error Handling**: Non-critical

---

### Step 6: Install ClickUp
**Function**: `stepInstallClickUp(config)`

**Purpose**: ClickUp collaboration tool installation

**Conditional**: Runs for "engineer" and "office" departments

**Operations**:
1. **Department Check**: Skip for "general"
2. **Winget Installation** (Primary method):
   ```powershell
   winget install --id 9NR1Q6L7FZQR --source msstore --accept-package-agreements
   ```
3. **Microsoft Store Fallback**:
   ```cmd
   start ms-windows-store://pdp/?productid=9NR1Q6L7FZQR
   ```
4. **User Notification**: Shows warning dialog for manual completion

**App ID**: `9NR1Q6L7FZQR` (Official ClickUp Microsoft Store ID)

**Error Handling**: Non-critical (fallback to manual installation)

---

### Step 7: Install System Updates
**Function**: `stepInstallSystemUpdates()`

**Purpose**: Security patches and system updates

**Operations**:
1. **System Restore Point**:
   ```powershell
   Checkpoint-Computer -Description "IMMX Pre-patch backup $(Get-Date)" -RestorePointType "MODIFY_SETTINGS"
   ```
2. **PSWindowsUpdate Module**:
   ```powershell
   Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
   Get-WUList  # Check available updates
   ```
3. **Network Patch Installation**:

**Patch Types and Commands**:
```go
patches := []struct {
    Name string
    Path string  
    Type string
}{
    {"Windows Security Update KB5028185", "windows10.0-kb5028185-x64.msu", "MSU"},
    {"Office Security Patch KB5002138", "office2016-kb5002138-fullfile-x64-glb.exe", "EXE"},
    {"Adobe Reader Update", "AcroRdrDCUpd1901220040.msp", "MSP"}, 
    {".NET Framework 4.8.1", "NDP481-KB4524152-x86-x64-AllOS-ENU.exe", "EXE"},
}
```

**Installation Commands by Type**:
- **MSU**: `wusa.exe "patch.msu" /quiet /norestart`
- **MSP**: `msiexec.exe /update "patch.msp" /quiet /norestart`  
- **EXE**: `patch.exe /S /quiet /norestart`

**Error Handling**: Non-critical (individual patch failures logged as warnings)

---

### Step 8: Configure Domain
**Function**: `stepConfigureDomain(config)`

**Purpose**: Domain user setup and network configuration

**Operations**:
1. **Domain Connectivity Test**:
   ```powershell
   Test-ComputerSecureChannel -Server "immx.local"
   ```
2. **User Profile Directory**:
   ```go
   profilePath := fmt.Sprintf(`C:\Users\%s`, config.Username)
   os.MkdirAll(profilePath, 0755)
   ```
3. **Network Drive Mapping**:
   ```powershell
   New-PSDrive -Name "H" -PSProvider FileSystem -Root "\\192.168.32.10\immx" -Persist
   ```
4. **Security Permissions**:
   ```powershell
   icacls "C:\Program Files" /grant "username:(OI)(CI)RX" /C /Q
   ```
5. **Group Policy Refresh**:
   ```powershell
   gpupdate /force
   ```

**Permission Flags Explained**:
- `(OI)`: Object Inherit
- `(CI)`: Container Inherit  
- `RX`: Read and Execute permissions

**Error Handling**: Non-critical (individual operations may fail without stopping deployment)

---

### Step 9: System Health Check
**Function**: `stepSystemHealthCheck()`

**Purpose**: System integrity and readiness verification

**Operations**:
1. **System File Check**:
   ```cmd
   sfc /verifyonly
   ```
2. **Service Status Check**:
   ```powershell
   Get-Service | Where-Object { $_.Status -eq "Stopped" -and $_.StartType -eq "Automatic" }
   ```
3. **Pending Reboot Detection**:
   ```powershell
   Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
   ```

**Reboot Detection Logic**:
- Registry key existence indicates pending reboot
- Sets `rebootRequired = true` if detected
- Combines with language pack reboot requirement

**Error Handling**: Non-critical (health check failures logged but don't stop deployment)

---

### Step 10: Handle System Reboot
**Function**: `stepHandleSystemReboot()`

**Purpose**: Manage system restart requirements

**Conditional Logic**:
```go
if !rebootRequired {
    writeLog("INFO", "No system reboot required")
    return nil
}
```

**User Interaction**:
```go
rebootNow := askYesNo("System Reboot Required", 
    "System reboot is required to complete installation.\n\nReboot now?")
```

**Reboot Now Path**:
1. **Desktop Reminder**: Creates completion notice
2. **Scheduled Reboot**:
   ```cmd
   shutdown /r /t 60 /c "IMMX Enterprise Software Deployment - Reboot Required"
   ```
3. **User Warning**: 60-second countdown dialog

**Manual Reboot Path**:
1. **Desktop Reminder**: Creates `IMMX_Reboot_Reminder.txt`
2. **Instructions**: Detailed next steps and support info

**Error Handling**: Non-critical (reboot scheduling failure falls back to manual)

---

### Step 11: Generate Deployment Summary
**Function**: `stepGenerateDeploymentSummary(config)`

**Purpose**: System information collection and verification

**Information Collected**:
1. **System Information**:
   ```powershell
   $computer = Get-WmiObject Win32_ComputerSystem
   $os = Get-WmiObject Win32_OperatingSystem  
   $bios = Get-WmiObject Win32_BIOS
   ```

2. **Software Verification**:
   ```powershell
   # Office Check
   Get-WmiObject Win32_Product | Where-Object {$_.Name -like "*Microsoft Office*"}
   
   # Adobe Check  
   Get-WmiObject Win32_Product | Where-Object {$_.Name -like "*Adobe*"}
   
   # ClickUp Check (Windows Store App)
   Get-AppxPackage | Where-Object {$_.Name -like "*ClickUp*"}
   ```

3. **Security Status**:
   ```powershell
   # Windows Defender
   Get-MpComputerStatus
   
   # Firewall Status
   Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true}
   ```

**Output Format**: Structured text summary with deployment statistics

**Error Handling**: Non-critical (information collection failures don't affect deployment success)

---

### Step 12: Finalize Deployment
**Function**: `stepFinalizeDeployment(config)`

**Purpose**: Cleanup and final status reporting

**Operations**:
1. **Log Finalization**: Final success entry with statistics
2. **Cleanup**: Removes temporary directory `C:\Temp\IMMX_Install`
3. **Status Message Generation**:
   ```go
   if errorCount == 0 && warningCount == 0 {
       statusMsg = "🎉 DEPLOYMENT COMPLETED SUCCESSFULLY!"
   } else {
       statusMsg = fmt.Sprintf("✅ DEPLOYMENT COMPLETED WITH WARNINGS\nErrors: %d\nWarnings: %d", 
           errorCount, warningCount)
   }
   ```
4. **Final Dialog**: Success/warning dialog with support information

**Success Criteria**:
- **Perfect**: 0 errors, 0 warnings
- **Successful with Issues**: >0 warnings, but no critical errors
- **Failed**: Critical error occurred (deployment would have stopped earlier)

---

## 🎛️ Command Line Usage

### Basic Execution
```bash
go run immx_deployment.go
```

### Debug Mode
```bash
go run immx_deployment.go --debug
```

**Debug Mode Features**:
- Detailed PowerShell command logging
- Step-by-step execution details
- Interactive error handling (ask user to continue on non-critical errors)
- Extended console output with debug messages

### Build Executable
```bash
go build -o immx_deployment.exe immx_deployment.go
```

---

## 📊 Error Classification System

### Critical Errors (Abort Deployment)
- **Step 1**: Network repository inaccessible
- **System Failures**: Cannot create directories, no admin rights

### Non-Critical Errors (Continue with Warnings)  
- **Software Installation**: Individual applications fail to install
- **Language Pack**: Chinese language configuration issues
- **Domain Configuration**: Network drive mapping failures
- **Health Checks**: System verification issues

### Warning Categories
- **File Not Found**: Update patches or installers missing
- **Permission Issues**: Limited user rights for certain operations  
- **Service Failures**: Non-essential service configuration problems
- **Information Collection**: System information gathering issues

---

## 📁 File System Operations

### Directory Structure Created
```
C:\
├── Windows\
│   └── Logs\
│       └── IMMX_Deployment.log          # Main log file
├── Temp\
│   └── IMMX_Install\                    # Temporary installation files
│       ├── office_config.xml            # Office installation config
│       └── [extracted installers]       # Temporary installer files
└── Users\
    └── [username]\
        └── Desktop\
            ├── IMMX_Installation_Complete.txt    # Success notification
            └── IMMX_Reboot_Reminder.txt          # Reboot reminder
```

### Network Paths Accessed
```
\\192.168.32.10\immx\01_Public_Infor\Software\
├── Office\
│   └── 2016\
│       ├── SW_DVD5_Office_Professional_Plus_2016_64Bit_ChnSimp_MLF_X20-42426.ISO
│       └── SW_DVD5_Office_Professional_Plus_2016_64Bit_English_MLF_X20-42432.ISO
├── AcroRdrDC1901220034_en_US.exe
├── CAXA 3D 2024\
│   └── Setup\
│       └── Setup.exe
└── Updates\
    ├── Windows\
    │   └── windows10.0-kb5028185-x64.msu
    ├── Office\
    │   └── office2016-kb5002138-fullfile-x64-glb.exe
    ├── Adobe\
    │   └── AcroRdrDCUpd1901220040.msp
    └── Framework\
        └── NDP481-KB4524152-x86-x64-AllOS-ENU.exe
```

---

## 🔒 Security Considerations

### Administrator Privileges
- **Recommended**: Run as Administrator for full functionality
- **Fallback**: Limited functionality with user privileges
- **Detection**: Automatic privilege level detection and warnings

### Network Security
- **UNC Path Access**: Requires domain authentication or mapped drives
- **Firewall**: May need exceptions for network repository access
- **Execution Policy**: PowerShell bypass policy used for system operations

### File System Security
- **Log Directory**: Creates secure log directory with proper permissions
- **Temp Files**: Secure temporary file handling with cleanup
- **User Profiles**: Respects existing user directory permissions

---

## 🐛 Troubleshooting Guide

### Common Issues and Solutions

**Issue**: Network repository not accessible
**Solution**: 
1. Check network connectivity to 192.168.32.10
2. Verify domain authentication
3. Manually map network drive: `net use Z: \\192.168.32.10\immx`

**Issue**: PowerShell execution policy errors
**Solution**: 
1. Run as Administrator
2. Set execution policy: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process`

**Issue**: Software installation failures
**Solution**:
1. Check file paths and permissions
2. Verify installer file integrity
3. Review detailed logs in `C:\Windows\Logs\IMMX_Deployment.log`

**Issue**: Chinese language pack installation fails
**Solution**:
1. Check Windows version compatibility
2. Ensure sufficient disk space
3. Run Windows Update to get latest language capabilities

### Debug Mode Benefits
- **Verbose Logging**: See exact PowerShell commands executed
- **Interactive Mode**: Choose to continue or abort on errors
- **Step Timing**: Performance monitoring for each step
- **Network Diagnostics**: Detailed network access attempts

---

## 📞 Support Information

### Contact Details
- **Help Desk**: +86-400-IMMX-HELP
- **Email**: support@immx.com  
- **Documentation**: `\\192.168.32.10\immx\Support\Docs\`

### Log Files
- **Main Log**: `C:\Windows\Logs\IMMX_Deployment.log`
- **Office Installation**: `%TEMP%\Microsoft Office Professional Plus Setup*.txt`
- **Windows Update**: Windows Update history in Settings

### System Requirements
- **OS**: Windows 10/11 (64-bit)
- **RAM**: 4GB minimum, 8GB recommended
- **Disk Space**: 10GB free space for software installations
- **Network**: Access to `\\192.168.32.10\immx` network share
- **Privileges**: Administrator rights recommended

---

## 🔄 Version History

**v2.1.3 - Current Release**
- Complete Go implementation
- Windows native dialog integration  
- Advanced error handling with step classification
- Real network path integration
- Debug mode support
- Comprehensive logging system

**Previous Versions**
- v2.0.x: PowerShell-only implementation
- v1.x: Manual installation scripts

---

This README provides complete documentation for understanding, deploying, and troubleshooting the IMMX Enterprise Software Deployment System. Each component is explained with practical examples and detailed technical specifications.
