function Show-Menu {
    Write-Host "Available Python scripts:" -ForegroundColor Blue
    Write-Host "1) cracker.py"
    Write-Host "2) FileCarver.py"
    Write-Host "3) vmescapetester.py" 
    Write-Host "4) wipier.py"
    Write-Host "5) Show help for ALL scripts"
    Write-Host "6) Exit"
}

function Show-Help {
    param($ScriptName)
    Write-Host "=== $ScriptName help ===" -ForegroundColor Green
    python $ScriptName --help
    Write-Host ""
}

while ($true) {
    Show-Menu
    $choice = Read-Host "`nSelect an option (1-6)"
    
    switch ($choice) {
        "1" { Show-Help "cracker.py" }
        "2" { Show-Help "FileCarver.py" }
        "3" { Show-Help "vmescapetester.py" }
        "4" { Show-Help "wipier.py" }
        "5" {
            Write-Host "=== Showing help for ALL scripts ===" -ForegroundColor Yellow
            Show-Help "cracker.py"
            Show-Help "FileCarver.py" 
            Show-Help "vmescapetester.py"
            Show-Help "wipier.py"
        }
        "6" { 
            Write-Host "Goodbye!" -ForegroundColor Green
            exit 
        }
        default { Write-Host "Invalid option! Please select 1-6." -ForegroundColor Red }
    }
}