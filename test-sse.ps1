param([string]$path, [string]$url = "http://localhost:8081/api/audit/dir-stream")
Add-Type -AssemblyName System.Net.Http

$handler = New-Object System.Net.Http.HttpClientHandler
$client = New-Object System.Net.Http.HttpClient($handler)
$client.Timeout = [TimeSpan]::FromMinutes(10)

$content = New-Object System.Net.Http.StringContent((@{path=$path} | ConvertTo-Json), [System.Text.Encoding]::UTF8, "application/json")
$response = $client.PostAsync($url, $content).Result
$stream = $response.Content.ReadAsStreamAsync().Result
$ms = New-Object System.IO.MemoryStream

Write-Host "HTTP Status: $($response.StatusCode)"
Write-Host "Content-Type: $($response.Content.Headers.ContentType)"
Write-Host "---"

$buffer = New-Object byte[] 4096
$rawOutput = ""

while ($true) {
    $read = $stream.Read($buffer, 0, $buffer.Length)
    if ($read -eq 0) { break }
    $ms.Write($buffer, 0, $read)
    $rawOutput += [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
}

$totalReceived = $ms.Length
$ms.Dispose()

$rawOutput | Out-File -FilePath "$PSScriptRoot\sse-raw-output.txt" -Encoding UTF8
Write-Host "Raw output saved to sse-raw-output.txt ($totalReceived bytes)"
Write-Host "---"

$lines = $rawOutput -split "`n"
$eventCount = 0
$errors = @()
$firstContent = $null

foreach ($line in $lines) {
    $line = $line.Trim()
    if ($line -eq "") { continue }

    if ($line.StartsWith("data:")) {
        $dataStr = $line.Substring(5).Trim()
        if ($dataStr -eq "[DONE]") {
            Write-Host "[DONE] event count: $eventCount"
            continue
        }
        $eventCount++
        try {
            $parsed = $dataStr | ConvertFrom-Json
            if ($parsed.PSObject.Properties.Name -contains "isError" -and $parsed.isError -eq $true) {
                Write-Host "[ERROR EVENT #$eventCount] isError=true : $($parsed.content)"
                $errors += $parsed.content
            } elseif ($parsed.PSObject.Properties.Name -contains "content") {
                $c = $parsed.content
                if (-not $firstContent) { $firstContent = $c }
                if ($eventCount -le 5) {
                    $preview = if ($c.Length -gt 80) { $c.Substring(0, 80) } else { $c }
                    Write-Host "[EVENT #$eventCount] content (len=$($c.Length)): $preview"
                } elseif ($eventCount % 30 -eq 0) {
                    Write-Host "[EVENT #$eventCount] content (len=$($c.Length)): [truncated]..."
                }
            }
        } catch {
            Write-Host "[PARSE ERROR #$eventCount] $dataStr"
        }
    } else {
        if ($line -match "^[^:]+:") {
            Write-Host "[META] $line"
        }
    }
}

Write-Host "---"
Write-Host "Summary: $totalReceived bytes, $eventCount events, $($errors.Count) errors"
if ($errors.Count -gt 0) {
    Write-Host "FAIL"
    exit 1
} else {
    Write-Host "PASS"
    exit 0
}
