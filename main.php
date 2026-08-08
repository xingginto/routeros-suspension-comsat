<?php

use Ubnt\UcrmPluginSdk\Service\PluginConfigManager;
use Ubnt\UcrmPluginSdk\Service\PluginLogManager;
use ComsatRouterOs\Service\Suspender;

require_once __DIR__ . '/vendor/autoload.php';

(static function () {
    $log = PluginLogManager::create();
    $log->clearLog();

    $config = (new PluginConfigManager())->loadConfig();

    try {
        $configs = Suspender::buildDeviceConfigs($config);
    } catch (\Exception $exception) {
        $log->appendLog($exception->getMessage());
        exit(1);
    }

    foreach ($configs as $config) {
        $error = false;
        try {
            $log->appendLog(sprintf('Process is starting [%s, %s]', $config['mikrotikIpAddress'], $config['mikrotikUserName']));
            (new Suspender($config))->suspend();
        } catch (\Exception $exception) {
            $error = true;
            $log->appendLog(sprintf('  - %s', $exception->getMessage()));
        }
        $log->appendLog(sprintf('Process is finished %s%s', $error ? '[ERROR]' : '[OK]', PHP_EOL));
    }
})();
