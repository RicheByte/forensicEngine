# FORENSIC ENGINE LAUNCHER - PowerShell Edition
# Enhanced with better connectivity and error handling

# ANSI Color Support for PowerShell
$host.UI.RawUI.WindowTitle = "Forensic Engine Launcher"

# Color functions
function Write-Title {
    param([string]$Message)
    Write-Host "`n$Message" -ForegroundColor Cyan -BackgroundColor Black
}

function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Error-Message {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor White
}

# Check Python installation and version
function Test-PythonInstallation {
    Write-Info "Checking Python installation..."
    
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Python found: $pythonVersion"
            return $true
        }
        else {
            Write-Error-Message "Python not found in PATH"
            Write-Warning "Please install Python from https://www.python.org/"
            return $false
        }
    }
    catch {
        Write-Error-Message "Python not found in PATH"
        Write-Warning "Please install Python from https://www.python.org/"
        return $false
    }
}

# Check if required Python packages are installed
function Test-PythonPackages {
    Write-Info "Checking required packages..."
    
    $requiredPackages = @(
        "argparse",
        "pathlib"
    )
    
    $missingPackages = @()
    
    foreach ($package in $requiredPackages) {
        $check = python -c "import $package" 2>&1
        if ($LASTEXITCODE -ne 0) {
            $missingPackages += $package
        }
    }
    
    if ($missingPackages.Count -gt 0) {
        Write-Warning "Missing packages: $($missingPackages -join ', ')"
        $install = Read-Host "Install missing packages? (Y/N)"
        if ($install -eq 'Y' -or $install -eq 'y') {
            foreach ($pkg in $missingPackages) {
                Write-Info "Installing $pkg..."
                pip install $pkg
            }
        }
    }
    else {
        Write-Success "All basic packages available"
    }
}

# Display main menu
function Show-Menu {
    Clear-Host
    Write-Title "============================================================="
    Write-Host "           " -NoNewline
    Write-Host "FORENSIC ENGINE LAUNCHER v2.0" -ForegroundColor Cyan -BackgroundColor DarkBlue
    Write-Title "============================================================="
    Write-Host ""
    Write-Host "  Available Tools:" -ForegroundColor Yellow
    Write-Host "  ---------------" -ForegroundColor Yellow
    Write-Host "  [1] " -NoNewline -ForegroundColor White
    Write-Host "cracker.py        " -NoNewline -ForegroundColor Cyan
    Write-Host "- Hash Identifier & Cracker" -ForegroundColor Gray
    
    Write-Host "  [2] " -NoNewline -ForegroundColor White
    Write-Host "FileCarver.py     " -NoNewline -ForegroundColor Cyan
    Write-Host "- Quantum File Carver" -ForegroundColor Gray
    
    Write-Host "  [3] " -NoNewline -ForegroundColor White
    Write-Host "vmescapetester.py " -NoNewline -ForegroundColor Cyan
    Write-Host "- VM Escape Tester" -ForegroundColor Gray
    
    Write-Host "  [4] " -NoNewline -ForegroundColor White
    Write-Host "wipier.py         " -NoNewline -ForegroundColor Cyan
    Write-Host "- Log Tamperer/Sanitizer" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "  Actions:" -ForegroundColor Yellow
    Write-Host "  --------" -ForegroundColor Yellow
    Write-Host "  [5] " -NoNewline -ForegroundColor White
    Write-Host "Show help for ALL tools" -ForegroundColor Magenta
    
    Write-Host "  [6] " -NoNewline -ForegroundColor White
    Write-Host "Run tool with custom arguments" -ForegroundColor Magenta
    
    Write-Host "  [7] " -NoNewline -ForegroundColor White
    Write-Host "Check Python environment" -ForegroundColor Magenta
    
    Write-Host "  [8] " -NoNewline -ForegroundColor White
    Write-Host "Install requirements" -ForegroundColor Magenta
    
    Write-Host "  [9] " -NoNewline -ForegroundColor White
    Write-Host "Open file location" -ForegroundColor Magenta
    
    Write-Host "  [0] " -NoNewline -ForegroundColor White
    Write-Host "Exit" -ForegroundColor Red
    
    Write-Title "============================================================="
}

# Show help for a specific script
function Show-ScriptHelp {
    param([string]$ScriptName)
    
    Write-Title "=== $ScriptName Help ==="
    
    if (Test-Path $ScriptName) {
        try {
            python $ScriptName --help
            if ($LASTEXITCODE -ne 0) {
                Write-Error-Message "Error displaying help for $ScriptName"
            }
        }
        catch {
            Write-Error-Message "Failed to execute $ScriptName"
            Write-Warning $_.Exception.Message
        }
    }
    else {
        Write-Error-Message "Script not found: $ScriptName"
    }
    
    Write-Host ""
}

# Run script with custom arguments
function Invoke-ScriptWithArgs {
    param([string]$ScriptName)
    
    if (-not (Test-Path $ScriptName)) {
        Write-Error-Message "Script not found: $ScriptName"
        return
    }
    
    Write-Info "Enter arguments for $ScriptName (or 'back' to return):"
    $args = Read-Host "Arguments"
    
    if ($args -eq 'back' -or $args -eq '') {
        return
    }
    
    Write-Info "Executing: python $ScriptName $args"
    Write-Host ""
    
    try {
        Invoke-Expression "python $ScriptName $args"
    }
    catch {
        Write-Error-Message "Execution failed: $($_.Exception.Message)"
    }
}

# Check and display Python environment info
function Show-PythonEnvironment {
    Write-Title "=== Python Environment Information ==="
    
    Write-Info "Python Version:"
    python --version
    
    Write-Host ""
    Write-Info "Python Executable Path:"
    python -c "import sys; print(sys.executable)"
    
    Write-Host ""
    Write-Info "Installed Packages:"
    pip list | Select-Object -First 20
    
    Write-Host ""
    Write-Warning "Showing first 20 packages. Run 'pip list' in terminal for full list."
}

# Install requirements from requirements.txt
function Install-Requirements {
    Write-Title "=== Installing Requirements ==="
    
    if (Test-Path "requirements.txt") {
        Write-Info "Found requirements.txt"
        $confirm = Read-Host "Install packages from requirements.txt? (Y/N)"
        
        if ($confirm -eq 'Y' -or $confirm -eq 'y') {
            Write-Info "Installing packages..."
            pip install -r requirements.txt
            
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Installation complete!"
            }
            else {
                Write-Error-Message "Installation failed. Check error messages above."
            }
        }
    }
    else {
        Write-Warning "requirements.txt not found in current directory"
        Write-Info "Creating basic requirements.txt..."
        
        $basicRequirements = @"
# Basic requirements for forensic tools
numpy
pandas
psutil
"@
        
        $basicRequirements | Out-File -FilePath "requirements.txt" -Encoding UTF8
        Write-Success "Created requirements.txt with basic packages"
    }
}

# Open the script directory in File Explorer
function Open-FileLocation {
    $currentPath = Get-Location
    Write-Info "Opening: $currentPath"
    Start-Process explorer.exe -ArgumentList $currentPath
}

# Main script execution
function Start-ForensicEngine {
    # Initial checks
    if (-not (Test-PythonInstallation)) {
        Write-Error-Message "Cannot continue without Python. Please install Python first."
        Read-Host "Press Enter to exit"
        return
    }
    
    # Main loop
    $running = $true
    
    while ($running) {
        Show-Menu
        Write-Host ""
        $choice = Read-Host "Select an option (0-9)"
        Write-Host ""
        
        switch ($choice) {
            '1' {
                Show-ScriptHelp "cracker.py"
                Read-Host "Press Enter to continue"
            }
            '2' {
                Show-ScriptHelp "FileCarver.py"
                Read-Host "Press Enter to continue"
            }
            '3' {
                Show-ScriptHelp "vmescapetester.py"
                Read-Host "Press Enter to continue"
            }
            '4' {
                Show-ScriptHelp "wipier.py"
                Read-Host "Press Enter to continue"
            }
            '5' {
                Write-Title "=== Showing Help for ALL Tools ==="
                Show-ScriptHelp "cracker.py"
                Show-ScriptHelp "FileCarver.py"
                Show-ScriptHelp "vmescapetester.py"
                Show-ScriptHelp "wipier.py"
                Read-Host "Press Enter to continue"
            }
            '6' {
                Write-Title "=== Run Tool with Custom Arguments ==="
                Write-Host "Available scripts:"
                Write-Host "  [1] cracker.py"
                Write-Host "  [2] FileCarver.py"
                Write-Host "  [3] vmescapetester.py"
                Write-Host "  [4] wipier.py"
                Write-Host ""
                $scriptChoice = Read-Host "Select script (1-4)"
                
                $scriptMap = @{
                    '1' = 'cracker.py'
                    '2' = 'FileCarver.py'
                    '3' = 'vmescapetester.py'
                    '4' = 'wipier.py'
                }
                
                if ($scriptMap.ContainsKey($scriptChoice)) {
                    Invoke-ScriptWithArgs $scriptMap[$scriptChoice]
                    Read-Host "Press Enter to continue"
                }
                else {
                    Write-Error-Message "Invalid selection"
                    Start-Sleep -Seconds 2
                }
            }
            '7' {
                Show-PythonEnvironment
                Read-Host "Press Enter to continue"
            }
            '8' {
                Install-Requirements
                Read-Host "Press Enter to continue"
            }
            '9' {
                Open-FileLocation
                Start-Sleep -Seconds 1
            }
            '0' {
                Write-Success "`nGoodbye! Stay forensic!"
                $running = $false
            }
            default {
                Write-Error-Message "Invalid option! Please select 0-9."
                Start-Sleep -Seconds 2
            }
        }
    }
}

# Start the application
Write-Host ""
Write-Title "============================================================="
Write-Host "  " -NoNewline
Write-Host "Welcome to Forensic Engine Launcher" -ForegroundColor Cyan
Write-Title "============================================================="
Write-Host ""

Start-ForensicEngine
