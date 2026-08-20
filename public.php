<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');

global $data;

if ($json = json_decode(file_get_contents("php://input"), true)) {
    $data['option'] = 'WebHook';
} else {
    $data = $_GET;
}

use Ubnt\UcrmPluginSdk\Service\PluginConfigManager;
use Ubnt\UcrmPluginSdk\Service\PluginLogManager;
use Ubnt\UcrmPluginSdk\Security\PermissionNames;
use Ubnt\UcrmPluginSdk\Service\UcrmSecurity;
use ComsatRouterOs\Service\Suspender;

require_once __DIR__ . '/vendor/autoload.php';

const PROGRESS_FILE = __DIR__ . '/data/sync-progress.json';
const EXPORT_FILE = __DIR__ . '/data/skipped-clients.csv';

/**
 * Send SSE event
 */
function sendEvent(string $message, string $type = 'info'): void
{
    echo "data: " . json_encode(['type' => $type, 'message' => $message]) . "\n\n";
    if (ob_get_level()) ob_flush();
    flush();
}

/**
 * @return array{phase1Done: string[], phase3Done: string[], ipList: string[]|null}|null
 */
function loadSyncProgress(): ?array
{
    if (! is_file(PROGRESS_FILE)) {
        return null;
    }
    $data = json_decode((string) file_get_contents(PROGRESS_FILE), true);
    return is_array($data) ? $data : null;
}

function saveSyncProgress(array $progress): void
{
    $dir = dirname(PROGRESS_FILE);
    if (! is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    $progress['updatedAt'] = date('c');
    file_put_contents(PROGRESS_FILE, json_encode($progress));
}

function clearSyncProgress(): void
{
    if (is_file(PROGRESS_FILE)) {
        unlink(PROGRESS_FILE);
    }
}

// Check if this is an AJAX sync request
if (isset($data['option']) && $data['option'] === 'ajax-sync') {
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');

    $security = UcrmSecurity::create();
    $user = $security->getUser();
    if (!$user || $user->isClient || !$user->hasViewPermission(PermissionNames::CLIENTS_SERVICES)) {
        sendEvent('Access denied', 'fatal');
        exit;
    }

    // Disable output buffering for streaming
    set_time_limit(0);
    if (ob_get_level()) ob_end_clean();
    ob_implicit_flush(true);

    $resume = isset($data['resume']) && $data['resume'] === '1';

    try {
        $config = (new PluginConfigManager())->loadConfig();

        try {
            $configs = Suspender::buildDeviceConfigs($config);
        } catch (\Exception $e) {
            sendEvent($e->getMessage(), 'fatal');
            exit;
        }

        $totalDevices = count($configs);

        // Display current date and time before starting
        $tzName = trim((string) ($config['timezone'] ?? ''));
        // Normalize "UTC+8"/"GMT+8" style to "+08:00" which PHP accepts
        if (preg_match('/^(?:UTC|GMT)([+-])(\d{1,2})(?::?(\d{2}))?$/i', $tzName, $tzm)) {
            $tzName = $tzm[1] . str_pad($tzm[2], 2, '0', STR_PAD_LEFT) . ':' . (isset($tzm[3]) && $tzm[3] !== '' ? $tzm[3] : '00');
        }
        try {
            $tz = new DateTimeZone($tzName ?: date_default_timezone_get());
        } catch (Exception $e) {
            $tz = new DateTimeZone(date_default_timezone_get());
        }
        $now = new DateTime('now', $tz);
        sendEvent('Date/Time: ' . $now->format('D, d M Y H:i:s') . ' (' . $tz->getName() . ')', 'info');
        sendEvent("Syncing {$totalDevices} device(s)...", 'info');

        // Load / reset the checkpoint
        $progress = null;
        if ($resume) {
            $progress = loadSyncProgress();
            if ($progress !== null) {
                sendEvent('Resuming previous sync from checkpoint...', 'info');
            } else {
                sendEvent('Continue requested, but no saved progress was found; starting a fresh sync.', 'info');
            }
        } else {
            clearSyncProgress();
        }
        $phase1Done = $progress['phase1Done'] ?? [];
        $phase3Done = $progress['phase3Done'] ?? [];
        $cachedIpList = $progress['ipList'] ?? null;

        // Build all suspender instances
        $suspenders = [];
        foreach ($configs as $cfg) {
            $suspenders[] = new Suspender($cfg, function ($msg, $type) {
                sendEvent($msg, $type);
            });
        }

        $persist = function () use (&$phase1Done, &$phase3Done, &$cachedIpList): void {
            saveSyncProgress([
                'phase1Done' => array_values($phase1Done),
                'phase3Done' => array_values($phase3Done),
                'ipList' => $cachedIpList,
            ]);
        };

        // Phase 1: sync firewall rules (walled garden, NAT, filter) to ALL devices
        sendEvent('--- Phase 1: Syncing firewall rules ---', 'info');
        foreach ($suspenders as $i => $suspender) {
            $devNum = $i + 1;
            $ip = $configs[$i]['mikrotikIpAddress'];
            if (in_array($ip, $phase1Done, true)) {
                sendEvent("Device {$devNum}/{$totalDevices}: {$ip} already done (Phase 1) - skipping", 'info');
                continue;
            }
            sendEvent("Processing device {$devNum}/{$totalDevices}: {$ip}", 'info');
            try {
                $suspender->suspendRules();
                $phase1Done[] = $ip;
                $persist();
            } catch (\Exception $e) {
                sendEvent("Error on {$ip}: " . $e->getMessage(), 'error');
            }
        }

        // Phase 2: fetch UISP suspension data ONCE (shared across all devices),
        // or reuse the cached list from a previous interrupted run.
        $ipList = [];
        if ($cachedIpList !== null) {
            $ipList = $cachedIpList;
            sendEvent('--- Phase 2: Using cached IP list from checkpoint (' . count($ipList) . ' IPs) ---', 'info');
        } else {
            sendEvent('--- Phase 2: Fetching suspension data from UISP ---', 'info');
            $exportRows = [];
            $suspenders[0]->setSkipCallback(function (int $clientId, string $label, string $reason) use (&$exportRows) {
                $exportRows[] = [$clientId, $label, $reason];
            });
            try {
                $ipList = $suspenders[0]->buildBlockIpList();
                $cachedIpList = $ipList;
                $persist();
            } catch (\Exception $e) {
                sendEvent('Error fetching UISP data: ' . $e->getMessage(), 'error');
            }

            if (!empty($exportRows)) {
                $dir = dirname(EXPORT_FILE);
                if (!is_dir($dir)) {
                    mkdir($dir, 0755, true);
                }
                $handle = fopen(EXPORT_FILE, 'w');
                if ($handle !== false) {
                    fputcsv($handle, ['Client ID', 'Client', 'Reason']);
                    foreach ($exportRows as $row) {
                        fputcsv($handle, $row);
                    }
                    fclose($handle);
                }
                sendEvent(count($exportRows) . ' client(s) skipped (no resolvable IP) - see Download CSV', 'warning');
            } elseif (is_file(EXPORT_FILE)) {
                unlink(EXPORT_FILE);
            }
        }

        // Phase 3: apply address list to ALL devices
        sendEvent('--- Phase 3: Applying address list to all devices ---', 'info');
        foreach ($suspenders as $i => $suspender) {
            $devNum = $i + 1;
            $ip = $configs[$i]['mikrotikIpAddress'];
            if (in_array($ip, $phase3Done, true)) {
                sendEvent("Device {$devNum}/{$totalDevices}: {$ip} already done (Phase 3) - skipping", 'info');
                continue;
            }
            sendEvent("Applying to device {$devNum}/{$totalDevices}: {$ip}", 'info');
            try {
                $suspender->applyBlockIpList($ipList);
                $phase3Done[] = $ip;
                $persist();
            } catch (\Exception $e) {
                sendEvent("Error on {$ip}: " . $e->getMessage(), 'error');
            }
        }

        // Fully completed - clear the checkpoint so the next run starts fresh.
        clearSyncProgress();

        sendEvent("Synchronization completed for {$totalDevices} device(s)", 'complete');

    } catch (\Exception $e) {
        sendEvent('Error: ' . $e->getMessage(), 'fatal');
    }
    exit;
}

// Lightweight JSON check used by the UI to know whether a "Continue" button
// should be offered (i.e. a previous run left a checkpoint on disk).
if (isset($data['option']) && $data['option'] === 'sync-status') {
    header('Content-Type: application/json');
    $security = UcrmSecurity::create();
    $user = $security->getUser();
    if (!$user || $user->isClient || !$user->hasViewPermission(PermissionNames::CLIENTS_SERVICES)) {
        echo json_encode(['progress' => null, 'exportReady' => false]);
        exit;
    }
    $progress = loadSyncProgress();
    echo json_encode([
        'progress' => $progress,
        'exportReady' => is_file(EXPORT_FILE),
    ]);
    exit;
}

// Download the CSV of clients skipped during the last run.
if (isset($data['option']) && $data['option'] === 'export-csv') {
    $security = UcrmSecurity::create();
    $user = $security->getUser();
    if (!$user || $user->isClient || !$user->hasViewPermission(PermissionNames::CLIENTS_SERVICES)) {
        http_response_code(403);
        echo "Access denied";
        exit;
    }
    if (! is_file(EXPORT_FILE)) {
        http_response_code(404);
        echo "No export available";
        exit;
    }
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="skipped-clients.csv"');
    header('Content-Length: ' . filesize(EXPORT_FILE));
    readfile(EXPORT_FILE);
    exit;
}

// Check if this is a webhook
if (isset($data['option']) && $data['option'] === 'WebHook') {
    // Send 200 response immediately so UISP doesn't timeout
    ignore_user_abort(true);
    set_time_limit(0);
    http_response_code(200);
    header('Connection: close');
    header('Content-Length: 0');
    if (ob_get_level()) ob_end_flush();
    flush();

    // Now process in background after response is sent
    $log = PluginLogManager::create();
    $config = (new PluginConfigManager())->loadConfig();

    // Determine the event and the affected service from the webhook payload
    $eventName = (string) ($json['eventName'] ?? '');
    $service = $json['extraData']['entity'] ?? [];
    if (empty($service['id']) && !empty($json['entityId'])) {
        $service['id'] = $json['entityId'];
    }

    try {
        $configs = Suspender::buildDeviceConfigs($config);
    } catch (\Exception $e) {
        $log->appendLog('Webhook: ' . $e->getMessage());
        exit;
    }

    if (empty($configs)) {
        $log->appendLog('Webhook: no MikroTik devices configured.');
        exit;
    }

    // One Suspender instance reused for the prepaid check + IP resolution
    $resolver = new Suspender($configs[0]);

    // Decide BLOCK vs UNBLOCK.
    // Hybrid: prepaid services re-check their active period (date-driven, fired via
    // service.edit); postpaid services use the event-name mapping.
    if (!empty($service['prepaid'])) {
        $serviceId = (int) ($service['id'] ?? 0);
        try {
            $hasActivePeriod = $resolver->hasActivePrepaidPeriod($serviceId);
        } catch (\Exception $e) {
            $log->appendLog('Webhook: failed to check prepaid period: ' . $e->getMessage());
            exit;
        }
        $action = $hasActivePeriod ? 'unblock' : 'block';
        $log->appendLog(sprintf(
            'Webhook: %s (prepaid service #%d, active period today: %s) -> %s',
            $eventName,
            $serviceId,
            $hasActivePeriod ? 'yes' : 'no',
            strtoupper($action)
        ));
    } else {
        $blockEvents = ['service.end', 'service.suspend'];
        $unblockEvents = ['service.postpone', 'service.suspend_cancel'];

        if (in_array($eventName, $blockEvents, true)) {
            $action = 'block';
        } elseif (in_array($eventName, $unblockEvents, true)) {
            $action = 'unblock';
        } else {
            $log->appendLog(sprintf('Webhook: ignoring event "%s" (postpaid)', $eventName));
            exit;
        }
        $log->appendLog(sprintf('Webhook: %s (service #%s) -> %s', $eventName, $service['id'] ?? '?', strtoupper($action)));
    }

    // Resolve the client's IP(s) once (device-independent), from the custom attribute
    try {
        $ips = $resolver->resolveServiceIps($service);
    } catch (\Exception $e) {
        $log->appendLog('Webhook: failed to resolve client IPs: ' . $e->getMessage());
        exit;
    }

    if (empty($ips)) {
        $log->appendLog('Webhook: no IPs found for this service in the client custom attribute; nothing to do.');
        exit;
    }
    $log->appendLog('Webhook: resolved ' . count($ips) . ' client IP(s) from attribute: ' . implode(', ', $ips));

    // Apply only to device(s) whose configured subnet contains the IP(s)
    $touched = false;
    foreach ($configs as $cfg) {
        try {
            $suspender = new Suspender($cfg);
            $matched = $suspender->matchesDeviceSubnets($ips);
            if (empty($matched)) {
                continue;
            }
            $touched = true;

            if ($action === 'block') {
                $n = $suspender->blockClientIps($ips);
                $log->appendLog(sprintf('Webhook: [%s] blocked %d IP(s)', $cfg['mikrotikIpAddress'], $n));
            } else {
                $n = $suspender->unblockClientIps($ips);
                $log->appendLog(sprintf('Webhook: [%s] unblocked %d IP(s)', $cfg['mikrotikIpAddress'], $n));
            }
        } catch (\Exception $e) {
            $log->appendLog(sprintf('Webhook error [%s]: %s', $cfg['mikrotikIpAddress'], $e->getMessage()));
        }
    }

    if (!$touched) {
        $log->appendLog('Webhook: client IP(s) did not match any device subnet; nothing applied.');
    }
    $log->appendLog('Webhook: finished');
    exit;
}

// Check if reset log
if (isset($data['option']) && $data['option'] === 'reset-log') {
    $security = UcrmSecurity::create();
    $user = $security->getUser();
    if (!$user || $user->isClient || !$user->hasViewPermission(PermissionNames::CLIENTS_SERVICES)) {
        http_response_code(403);
        echo "Access denied";
        exit;
    }
    $logger = PluginLogManager::create();
    $logger->clearLog();
    echo "<br> Log Cleared";
    exit;
}

// Default: Show UI
$security = UcrmSecurity::create();
$user = $security->getUser();
if (!$user || $user->isClient || !$user->hasViewPermission(PermissionNames::CLIENTS_SERVICES)) {
    http_response_code(403);
    echo "Access denied";
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RouterOS Suspension Comsat Sync</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 20px; background: #f5f5f5; margin: 0; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h2 { color: #333; margin-top: 0; display: flex; align-items: center; gap: 10px; }
        h2 svg { width: 32px; height: 32px; }
        .hint { color: #555; font-size: 13px; margin: 0 0 15px; }
        .progress-log { background: #1a1a2e; color: #eee; padding: 15px; border-radius: 6px; font-family: 'Monaco', 'Consolas', monospace; font-size: 13px; height: 400px; overflow-y: auto; }
        .log-entry { padding: 5px 8px; border-bottom: 1px solid #2d2d44; }
        .log-entry:last-child { border-bottom: none; }
        .log-time { color: #888; margin-right: 10px; }
        .log-info { color: #64b5f6; }
        .log-success { color: #81c784; }
        .log-warning { color: #ffb74d; }
        .log-error { color: #e57373; }
        .log-fatal { color: #e57373; font-weight: bold; }
        .log-complete { color: #4caf50; font-weight: bold; }
        .log-sync { color: #ce93d8; }
        .status-bar { margin-top: 15px; padding: 12px 15px; background: #e3f2fd; border-radius: 6px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .status-bar.running { background: #fff3e0; }
        .status-bar.success { background: #e8f5e9; }
        .status-bar.error { background: #ffebee; }
        .spinner { width: 20px; height: 20px; border: 3px solid #ddd; border-top-color: #2196f3; border-radius: 50%; animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .btn { padding: 10px 20px; background: #2196f3; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
        .btn:hover { background: #1976d2; }
        .btn:disabled { background: #ccc; cursor: not-allowed; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-card.blocked { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .stat-card.devices { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
        .stat-number { font-size: 28px; font-weight: bold; }
        .stat-label { font-size: 12px; opacity: 0.9; }
    </style>
</head>
<body>
    <div class="container">
        <h2>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
            </svg>
            RouterOS Suspension Comsat Sync v1.0.1
        </h2>
        <p class="hint">Blocks/unblocks each client's IP(s), resolved from a client custom attribute (not the Network/NMS app). Multiple comma-separated IPs are all blocked/unblocked together. If a run is interrupted, use <strong>Continue Sync</strong> to resume without restarting from Phase 1.</p>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="servicesCount">-</div>
                <div class="stat-label">Suspended Services</div>
            </div>
            <div class="stat-card blocked">
                <div class="stat-number" id="ipsCount">-</div>
                <div class="stat-label">Blocked IPs</div>
            </div>
            <div class="stat-card devices">
                <div class="stat-number" id="devicesCount">-</div>
                <div class="stat-label">MikroTik Devices</div>
            </div>
        </div>

        <div class="progress-log" id="log">
            <div class="log-entry"><span class="log-time">[--:--:--]</span><span class="log-info">→ Ready to sync. Click "Start Sync" or wait for auto-start...</span></div>
        </div>

        <div class="status-bar" id="status">
            <button class="btn" id="syncBtn" onclick="startSync(false)">Start Sync</button>
            <button class="btn" id="continueBtn" onclick="startSync(true)" style="display:none; background:#43a047;">Continue Sync</button>
            <a class="btn" id="exportBtn" href="?option=export-csv" style="display:none; background:#757575; text-decoration:none;">Download CSV (skipped clients)</a>
            <span id="statusText">Waiting to start...</span>
        </div>
    </div>

    <script>
        const logDiv = document.getElementById('log');
        const statusBar = document.getElementById('status');
        const statusText = document.getElementById('statusText');
        const syncBtn = document.getElementById('syncBtn');
        const continueBtn = document.getElementById('continueBtn');
        const exportBtn = document.getElementById('exportBtn');
        let isRunning = false;

        function addLog(message, type = 'info') {
            const time = new Date().toLocaleTimeString('en-US', {hour12: false});
            const icons = { success: '✓', error: '✗', fatal: '✗', warning: '⚠', complete: '★', info: '→', sync: '↻' };
            const icon = icons[type] || '→';
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            entry.innerHTML = '<span class="log-time">[' + time + ']</span><span class="log-' + type + '">' + icon + ' ' + message + '</span>';
            logDiv.appendChild(entry);
            logDiv.scrollTop = logDiv.scrollHeight;

            const servicesMatch = message.match(/Found (\d+) suspended services/);
            if (servicesMatch) {
                document.getElementById('servicesCount').textContent = servicesMatch[1];
            }
            const ipsMatch = message.match(/Found (\d+) IPs to block/);
            if (ipsMatch) {
                document.getElementById('ipsCount').textContent = ipsMatch[1];
            }
            const devicesMatch = message.match(/Processing device (\d+)\/(\d+)/);
            if (devicesMatch) {
                document.getElementById('devicesCount').textContent = devicesMatch[2];
            }
        }

        let hasCheckpoint = false;

        function checkProgress() {
            return fetch('?option=sync-status').then(function (r) { return r.json(); }).then(function (data) {
                const p = data.progress;
                if (p && ((p.phase1Done && p.phase1Done.length) || (p.phase3Done && p.phase3Done.length) || p.ipList)) {
                    hasCheckpoint = true;
                    const done = (p.phase1Done ? p.phase1Done.length : 0) + (p.phase3Done ? p.phase3Done.length : 0);
                    continueBtn.style.display = 'inline-block';
                    continueBtn.textContent = 'Continue Sync (' + done + ' step(s) done)';
                    syncBtn.textContent = 'Start Over';
                } else {
                    hasCheckpoint = false;
                    continueBtn.style.display = 'none';
                    syncBtn.textContent = 'Start Sync';
                }
                exportBtn.style.display = data.exportReady ? 'inline-block' : 'none';
            }).catch(function () {});
        }

        function startSync(resume) {
            if (isRunning) return;
            isRunning = true;

            logDiv.innerHTML = '';
            addLog(resume ? 'Continuing synchronization from last checkpoint...' : 'Starting synchronization...', 'info');

            syncBtn.disabled = true;
            continueBtn.disabled = true;
            statusBar.className = 'status-bar running';
            statusText.innerHTML = '<div class="spinner"></div> Syncing in progress...';

            const eventSource = new EventSource('?option=ajax-sync' + (resume ? '&resume=1' : ''));

            eventSource.onmessage = function(e) {
                try {
                    const data = JSON.parse(e.data);
                    addLog(data.message, data.type);

                    if (data.type === 'complete' || data.type === 'fatal') {
                        eventSource.close();
                        isRunning = false;
                        syncBtn.disabled = false;
                        continueBtn.disabled = false;
                        statusBar.className = 'status-bar ' + (data.type === 'complete' ? 'success' : 'error');
                        statusText.textContent = data.type === 'complete' ? 'Sync completed!' : 'Sync failed!';
                        checkProgress();
                    } else if (data.type === 'error') {
                        // Per-device errors are non-fatal and logged inline; the
                        // backend keeps syncing remaining devices. Closing the
                        // stream here would abort that in-progress PHP script
                        // (no ignore_user_abort on this branch), so just log it.
                        statusText.textContent = 'Syncing (error on a device, continuing)...';
                    }
                } catch(err) {
                    addLog(e.data, 'info');
                }
            };

            eventSource.onerror = function() {
                eventSource.close();
                isRunning = false;
                syncBtn.disabled = false;
                continueBtn.disabled = false;
                addLog('Stream closed — progress up to the last completed step was saved. Click "Continue Sync" to resume.', 'warning');
                statusBar.className = 'status-bar';
                statusText.textContent = 'Ready (click Continue Sync to resume)';
                checkProgress();
            };
        }

        // Auto-start after 2 seconds; resume automatically if a checkpoint exists.
        checkProgress().then(function () {
            setTimeout(function () { startSync(hasCheckpoint); }, 2000);
        });
    </script>
</body>
</html>
