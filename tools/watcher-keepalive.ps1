# Restarts the utilization watcher and the design agent if their node
# processes have died. Scheduled every 30 minutes by "MyRxCard Watcher Keepalive".
$procs = Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue
if (-not ($procs | Where-Object { $_.CommandLine -match "watch-utilization" })) {
  schtasks /Run /TN "MyRxCard Utilization Watcher" | Out-Null
}
if (-not ($procs | Where-Object { $_.CommandLine -match "agent\.mjs" })) {
  Start-Process -WindowStyle Hidden cmd -ArgumentList "/c", "C:\Users\trevo\myrxcard-docs-worker\agent\start-agent.local.cmd"
}
