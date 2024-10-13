## Evtx Command 
loops through all logs in the defined folders then outputs to cvs in defined folders 
```powershell
# Paths to Event Logs for Victim 1 and Victim 2
$vic1EvtxDir = "C:\Users\Flare\Documents\EventLogs\Vic1"
$vic2EvtxDir = "C:\Users\Flare\Documents\EventLogs\Vic2"

# Output directories for CSV files
$vic1CsvDir = "C:\Users\Flare\Documents\EventLogs\Vic1CSV"
$vic2CsvDir = "C:\Users\Flare\Documents\EventLogs\Vic2CSV"

# Path to EvtxECmd executable
$evtxCmdPath = "C:\Tools\net6\EvtxECmd\EvtxECmd.exe"

# Ensure the output directories exist (create them if necessary)
foreach ($dir in @($vic1CsvDir, $vic2CsvDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory
        Write-Host "Created directory: $dir"
    }
}

# Function to process EVTX files and output to CSV
function Process-EvtxFiles {
    param (
        [string]$evtxDir,  # Directory containing EVTX files
        [string]$csvDir    # Directory to output CSV files
    )
    
    # Get all .evtx files in the specified directory
    $evtxFiles = Get-ChildItem -Path $evtxDir -Filter *.evtx

    foreach ($evtxFile in $evtxFiles) {
        # Get the file name without the extension
        $fileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($evtxFile.Name)

        # Define the CSV output file name
        $csvFileName = "$fileNameWithoutExtension.csv"
        $csvOutputPath = Join-Path $csvDir $csvFileName

        # Run EvtxECmd to process the .evtx file and output to the CSV file
        Write-Host "Processing $($evtxFile.FullName) -> $csvOutputPath" -ForegroundColor Cyan
        & $evtxCmdPath -f $evtxFile.FullName --csv $csvDir --csvf $csvFileName

        # Output progress to console
        Write-Host "Processed $($evtxFile.Name) -> $csvOutputPath" -ForegroundColor Green
    }
}

# Process Victim 1's EVTX files
Write-Host "Processing Victim 1 EVTX files..." -ForegroundColor Yellow
Process-EvtxFiles -evtxDir $vic1EvtxDir -csvDir $vic1CsvDir

# Process Victim 2's EVTX files
Write-Host "Processing Victim 2 EVTX files..." -ForegroundColor Yellow
Process-EvtxFiles -evtxDir $vic2EvtxDir -csvDir $vic2CsvDir

Write-Host "All EVTX files processed successfully!" -ForegroundColor Cyan

```
