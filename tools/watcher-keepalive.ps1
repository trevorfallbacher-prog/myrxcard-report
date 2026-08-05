# Restarts the utilization watcher if its node process has died.
# Scheduled every 30 minutes by "MyRxCard Watcher Keepalive", which launches
# this via run-hidden.vbs so no console window ever appears.
$procs = Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue
if (-not ($procs | Where-Object { $_.CommandLine -match "watch-utilization" })) {
  schtasks /Run /TN "MyRxCard Utilization Watcher" | Out-Null
}
# Design agent (Illustrator/InDesign) keepalive removed 2026-08-05 per Trevor —
# it kept relaunching and popping windows over games. Restart it manually with
# C:\Users\trevo\myrxcard-docs-worker\agent\start-agent.local.cmd if needed.
