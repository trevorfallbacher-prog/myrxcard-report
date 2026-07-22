# Restarts the utilization watcher if its node process has died.
# Scheduled every 30 minutes by the "MyRxCard Watcher Keepalive" task.
$alive = Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -match "watch-utilization" }
if (-not $alive) { schtasks /Run /TN "MyRxCard Utilization Watcher" | Out-Null }
