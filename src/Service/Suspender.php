<?php

declare(strict_types=1);


namespace ComsatRouterOs\Service;

use Nette\Utils\Strings;
use Ubnt\UcrmPluginSdk\Exception\ConfigurationException;
use Ubnt\UcrmPluginSdk\Service\UcrmApi;

class Suspender
{
    private const BLOCKED_USERS_LIST = 'BLOCKED_USERS';
    private const WALLED_GARDEN_LIST = 'walled-garden';
    private const COMMENT_SIGNATURE = 'ucrm_';

    private const SERVICE_STATUS_ACTIVE = 3;
    private const SERVICE_STATUS_SERVICE_ACTIVE = 1;

    /**
     * @var UcrmApi
     */
    private $ucrmApi;

    /**
     * @var RouterOsApi
     */
    private $routerOsApi;

    /**
     * @var string[]
     */
    private $config;

    /**
     * @var callable|null
     */
    private $eventCallback;

    /**
     * @var int
     */
    private $lastHeartbeat = 0;

    /** @var string Configured client custom attribute name (default "IP Address"). */
    private $attributeName = 'IP Address';

    /** @var int|null Resolved custom attribute id. */
    private $attributeId = null;

    /** @var string|null Resolved custom attribute key. */
    private $attributeKey = null;

    /** @var array<int, array>|null Cache of all clients (active + archived), keyed by id. */
    private $allClientsCache = null;

    /** @var callable|null Called with (clientId, label, reason) when a suspend candidate has no resolvable IP. */
    private $skipCallback = null;

    public function __construct(array $config, ?callable $eventCallback = null)
    {
        $this->config = $config;
        $this->eventCallback = $eventCallback;
        $this->ucrmApi = UcrmApi::create();
        $this->routerOsApi = RouterOsApi::create($config);

        $name = trim((string) ($config['attributeName'] ?? ''));
        if ($name !== '') {
            $this->attributeName = $name;
        }
    }

    /**
     * Registers a callback invoked with (int $clientId, string $label, string $reason)
     * whenever a suspend/unblock candidate client has no resolvable IP. Used by the
     * bulk sync UI to build a CSV export of skipped clients.
     */
    public function setSkipCallback(?callable $callback): void
    {
        $this->skipCallback = $callback;
    }

    /**
     * Parse the global plugin config (parallel textareas) into one config array
     * per MikroTik device. Each device config includes a 'mikrotikSubnets' array
     * (line N of the Subnet field maps to device N; multiple subnets comma-separated).
     *
     * @return array[] one config array per device
     * @throws ConfigurationException when IP and User name row counts differ
     */
    public static function buildDeviceConfigs(array $config): array
    {
        $ipAddresses = array_map('trim', explode(PHP_EOL, (string) ($config['mikrotikIpAddress'] ?? '')));
        $userNames   = array_map('trim', explode(PHP_EOL, (string) ($config['mikrotikUserName'] ?? '')));
        $passwords   = array_map('trim', explode(PHP_EOL, (string) ($config['mikrotikPassword'] ?? '')));
        $subnetLines = array_map('trim', explode(PHP_EOL, (string) ($config['mikrotikSubnets'] ?? '')));

        $ipAddresses = array_values(array_filter($ipAddresses, static fn($v) => $v !== ''));
        $userNames   = array_values(array_filter($userNames, static fn($v) => $v !== ''));

        if (count($ipAddresses) !== count($userNames)) {
            throw new ConfigurationException('Number of rows in IP Address and User name fields does not match.');
        }

        $configs = [];
        foreach ($ipAddresses as $i => $ipAddress) {
            $subnetLine = $subnetLines[$i] ?? '';
            $subnets = array_values(array_filter(
                array_map('trim', explode(',', $subnetLine)),
                static fn($v) => $v !== ''
            ));

            $configs[] = array_merge($config, [
                'mikrotikIpAddress' => $ipAddress,
                'mikrotikUserName'  => $userNames[$i],
                'mikrotikPassword'  => $passwords[$i] ?? '',
                'mikrotikSubnets'   => $subnets,
            ]);
        }

        return $configs;
    }

    private function emit(string $message, string $type = 'info'): void
    {
        if ($this->eventCallback) {
            ($this->eventCallback)($message, $type);
            $this->lastHeartbeat = time();
        }
    }

    private function heartbeat(): void
    {
        if (!$this->eventCallback) return;
        $now = time();
        if ($this->lastHeartbeat === 0) {
            $this->lastHeartbeat = $now;
            return;
        }
        if ($now - $this->lastHeartbeat >= 25) {
            echo ": keep-alive\n\n";
            if (ob_get_level()) ob_flush();
            flush();
            $this->lastHeartbeat = $now;
        }
    }

    public function suspend(): void
    {
        $this->suspendRules();
        $ipAddresses = $this->buildBlockIpList();
        $this->applyBlockIpList($ipAddresses);
    }

    public function suspendRules(): void
    {
        if (! $this->validateConfig($this->config)) {
            throw new ConfigurationException('Missing value in plugin configuration.');
        }

        $captivePortalIp = $this->config['captivePortalIp'];

        // Build walled garden: captive portal IP + any extra IPs from config
        $walledGardenIps = [$captivePortalIp];
        if (!empty($this->config['walledGardenIps'])) {
            $extras = array_filter(array_map('trim', explode(PHP_EOL, $this->config['walledGardenIps'])));
            $walledGardenIps = array_values(array_unique(array_merge($walledGardenIps, $extras)));
        }

        $host = $this->config['mikrotikIpAddress'] ?? '';
        $this->emit("Logging in to {$host}...", 'sync');
        $this->routerOsApi->connect();

        $this->emit('Syncing walled garden (' . count($walledGardenIps) . ' IPs)...', 'sync');
        $this->syncWalledGarden($walledGardenIps);
        $this->emit('Walled garden synced', 'success');

        $this->emit('Syncing NAT rules...', 'sync');
        $this->syncNatRules($captivePortalIp);
        $this->emit('NAT rules synced', 'success');

        $this->emit('Syncing filter rules...', 'sync');
        $this->syncFilterRules();
        $this->emit('Filter rules synced', 'success');

        $this->routerOsApi->disconnect();
        $this->emit("Logged out from {$host}", 'info');
    }

    public function buildBlockIpList(): array
    {
        if (! $this->resolveAttribute()) {
            $this->emit(sprintf(
                'Client custom attribute "%s" was not found. Create it in UISP (System > Custom attributes) as a CLIENT attribute.',
                $this->attributeName
            ), 'error');
            return [];
        }

        $clientIds = [];

        $activePrepaidServiceIds = $this->fetchActivePrepaidPeriodServiceIds();

        $services = $this->findServicesToSuspend();
        $this->emit('Found ' . count($services) . ' suspended services', 'info');

        foreach ($services as $service) {
            $serviceId = $service['id'] ?? null;
            if ($serviceId !== null && isset($activePrepaidServiceIds[$serviceId])) {
                continue;
            }
            if ($service['clientId'] ?? false) {
                $clientIds[] = $service['clientId'];
            }
        }

        $expiredPrepaidServices = $this->findPrepaidServicesWithoutActivePeriod($activePrepaidServiceIds);
        $this->emit('Found ' . count($expiredPrepaidServices) . ' prepaid services with no active period', 'info');

        foreach ($expiredPrepaidServices as $service) {
            if ($service['clientId'] ?? false) {
                $clientIds[] = $service['clientId'];
            }
        }

        $clientIds = array_values(array_unique($clientIds));
        $this->emit('Found ' . count($clientIds) . ' client(s) to block', 'info');

        $ipAddresses = $this->resolveIpsFromClientAttribute($clientIds);
        $this->emit('Found ' . count($ipAddresses) . ' IPs to block', 'info');

        return $ipAddresses;
    }

    public function applyBlockIpList(array $ipAddresses): void
    {
        // Filter IPs to only those within this device's configured subnets
        $subnets = $this->getConfiguredSubnets();
        if (!empty($subnets)) {
            $filtered = $this->filterIpsBySubnets($ipAddresses, $subnets);
            $this->emit(
                'Subnet filter: ' . count($subnets) . ' subnet(s) — ' .
                count($filtered) . '/' . count($ipAddresses) . ' IPs match this device',
                'info'
            );
            $ipAddresses = $filtered;
        } else {
            $this->emit('No subnet filter — applying all ' . count($ipAddresses) . ' IPs', 'info');
        }

        $host = $this->config['mikrotikIpAddress'] ?? '';
        $this->emit("Logging in to {$host}...", 'sync');
        $this->routerOsApi->connect();

        $this->emit('Syncing address list...', 'sync');
        $this->setIpFirewallAddressList($ipAddresses);
        $this->emit('Address list synced', 'success');

        $this->routerOsApi->disconnect();
        $this->emit("Logged out from {$host}", 'info');
    }

    /**
     * Resolve a client service's IP address(es) from the client's custom attribute.
     * Accepts a service array (from a webhook payload) or fetches it by id.
     *
     * @return string[]
     */
    public function resolveServiceIps(array $service): array
    {
        $clientId = $service['clientId'] ?? null;

        if (!$clientId && !empty($service['id'])) {
            try {
                $fetched = $this->ucrmApi->get(sprintf('clients/services/%s', $service['id']));
                $clientId = $fetched['clientId'] ?? null;
            } catch (\Exception $e) {
                // ignore, handled below
            }
        }

        if (!$clientId) {
            return [];
        }

        if (! $this->resolveAttribute()) {
            return [];
        }

        try {
            $client = $this->ucrmApi->get(sprintf('clients/%s', $clientId));
        } catch (\Exception $e) {
            return [];
        }

        return $this->getClientIps($client);
    }

    /**
     * Return the subset of IPs that fall within this device's configured subnets.
     * If no subnet is configured for the device, all IPs are returned.
     *
     * @param string[] $ips
     * @return string[]
     */
    public function matchesDeviceSubnets(array $ips): array
    {
        $subnets = $this->getConfiguredSubnets();
        if (empty($subnets)) {
            return array_values($ips);
        }

        return $this->filterIpsBySubnets($ips, $subnets);
    }

    /**
     * Add the given client IP(s) to this device's BLOCKED_USERS list.
     * Only IPs not already present (with the ucrm_ prefix) are added.
     *
     * @param string[] $ips
     * @return int number of IPs added
     */
    public function blockClientIps(array $ips): int
    {
        $ips = $this->matchesDeviceSubnets($ips);
        if (empty($ips)) {
            return 0;
        }

        $this->routerOsApi->connect();

        $attributes = ['list', 'address', 'comment'];
        $routerList = $this->createIndex($this->findAndFilterUcrmIpAddressListOnRouter(), $attributes);
        $desired = $this->createIndex($this->createCrmIpAddressLists($ips), $attributes);

        $toAdd = array_diff_key($desired, $routerList);
        $this->addAddress($toAdd);

        $this->routerOsApi->disconnect();

        return count($toAdd);
    }

    /**
     * Remove the given client IP(s) from this device's BLOCKED_USERS list.
     * Only entries created by this plugin (ucrm_ prefix) are removed.
     *
     * @param string[] $ips
     * @return int number of IPs removed
     */
    public function unblockClientIps(array $ips): int
    {
        $ips = $this->matchesDeviceSubnets($ips);
        if (empty($ips)) {
            return 0;
        }

        $this->routerOsApi->connect();

        $ipSet = array_flip($ips);
        $toRemove = [];
        foreach ($this->findAndFilterUcrmIpAddressListOnRouter() as $entry) {
            if (isset($entry['address'], $ipSet[$entry['address']])) {
                $toRemove[] = $entry;
            }
        }

        $this->removeAddress($toRemove);

        $this->routerOsApi->disconnect();

        return count($toRemove);
    }

    /**
     * Subnets configured for this device via the "Subnet to sync" field.
     * @return string[]
     */
    private function getConfiguredSubnets(): array
    {
        $subnets = $this->config['mikrotikSubnets'] ?? [];
        if (is_string($subnets)) {
            $subnets = array_map('trim', explode(',', $subnets));
        }
        return array_values(array_filter((array) $subnets, static fn($v) => $v !== ''));
    }

    private function filterIpsBySubnets(array $ipAddresses, array $subnets): array
    {
        return array_values(array_filter($ipAddresses, function (string $ip) use ($subnets): bool {
            foreach ($subnets as $subnet) {
                if ($this->ipInRange($ip, $subnet)) {
                    return true;
                }
            }
            return false;
        }));
    }

    private function ipInRange(string $ip, string $range): bool
    {
        if (strpos($range, '/') !== false) {
            [$network, $mask] = explode('/', $range, 2);
            if (strpos($mask, '.') !== false) {
                $maskDec = ip2long($mask);
                return (ip2long($ip) & $maskDec) === (ip2long($network) & $maskDec);
            }
            $x = explode('.', $network);
            while (count($x) < 4) $x[] = '0';
            $network = implode('.', $x);
            $wildcard = pow(2, (32 - (int)$mask)) - 1;
            $maskDec = ~$wildcard;
            return (ip2long($ip) & $maskDec) === (ip2long($network) & $maskDec);
        }
        if (strpos($range, '*') !== false) {
            $lower = str_replace('*', '0', $range);
            $upper = str_replace('*', '255', $range);
            $range = "{$lower}-{$upper}";
        }
        if (strpos($range, '-') !== false) {
            [$lower, $upper] = explode('-', $range, 2);
            $ipDec = (float) sprintf('%u', ip2long($ip));
            return $ipDec >= (float) sprintf('%u', ip2long($lower))
                && $ipDec <= (float) sprintf('%u', ip2long($upper));
        }
        return $ip === $range;
    }

    private function syncNatRules(string $captivePortalIp): void
    {
        $rules = [
            [
                'chain'            => 'dstnat',
                'action'           => 'accept',
                'comment'          => 'captive_walled_garden_bypass',
                'src-address-list' => self::BLOCKED_USERS_LIST,
                'dst-address-list' => self::WALLED_GARDEN_LIST,
                'protocol'         => '',
                'dst-port'         => '',
                'to-addresses'     => '',
                'to-ports'         => '',
                'src-address'      => '',
                'dst-address'      => '',
                'out-interface'    => '',
                'jump-target'      => '',
            ],
            [
                'chain'            => 'dstnat',
                'action'           => 'dst-nat',
                'comment'          => 'captive_dns_udp',
                'src-address-list' => self::BLOCKED_USERS_LIST,
                'protocol'         => 'udp',
                'dst-port'         => 53,
                'to-addresses'     => $captivePortalIp,
                'to-ports'         => 53,
                'dst-address-list' => '',
                'src-address'      => '',
                'dst-address'      => '',
                'out-interface'    => '',
                'jump-target'      => '',
            ],
            [
                'chain'            => 'dstnat',
                'action'           => 'dst-nat',
                'comment'          => 'captive_dns_tcp',
                'src-address-list' => self::BLOCKED_USERS_LIST,
                'protocol'         => 'tcp',
                'dst-port'         => 53,
                'to-addresses'     => $captivePortalIp,
                'to-ports'         => 53,
                'dst-address-list' => '',
                'src-address'      => '',
                'dst-address'      => '',
                'out-interface'    => '',
                'jump-target'      => '',
            ],
            [
                'chain'            => 'dstnat',
                'action'           => 'dst-nat',
                'comment'          => 'captive_http',
                'src-address-list' => self::BLOCKED_USERS_LIST,
                'protocol'         => 'tcp',
                'dst-port'         => 80,
                'to-addresses'     => $captivePortalIp,
                'to-ports'         => 80,
                'dst-address-list' => '',
                'src-address'      => '',
                'dst-address'      => '',
                'out-interface'    => '',
                'jump-target'      => '',
            ],
            [
                'chain'            => 'dstnat',
                'action'           => 'dst-nat',
                'comment'          => 'captive_https',
                'src-address-list' => self::BLOCKED_USERS_LIST,
                'protocol'         => 'tcp',
                'dst-port'         => 443,
                'to-addresses'     => $captivePortalIp,
                'to-ports'         => 443,
                'dst-address-list' => '',
                'src-address'      => '',
                'dst-address'      => '',
                'out-interface'    => '',
                'jump-target'      => '',
            ],
        ];

        $this->setNat($rules);
    }

    private function syncFilterRules(): void
    {
        $rules = [
            [
                'chain'            => 'forward',
                'comment'          => 'captive_block_quic',
                'src-address-list' => self::BLOCKED_USERS_LIST,
                'protocol'         => 'udp',
                'dst-port'         => 443,
                'action'           => 'drop',
                'src-address'      => '',
                'dst-address'      => '',
                'dst-address-list' => '',
            ],
            [
                'chain'            => 'forward',
                'comment'          => 'captive_block_dot_tcp',
                'src-address-list' => self::BLOCKED_USERS_LIST,
                'protocol'         => 'tcp',
                'dst-port'         => 853,
                'action'           => 'drop',
                'src-address'      => '',
                'dst-address'      => '',
                'dst-address-list' => '',
            ],
            [
                'chain'            => 'forward',
                'comment'          => 'captive_block_dot_udp',
                'src-address-list' => self::BLOCKED_USERS_LIST,
                'protocol'         => 'udp',
                'dst-port'         => 853,
                'action'           => 'drop',
                'src-address'      => '',
                'dst-address'      => '',
                'dst-address-list' => '',
            ],
            [
                'chain'            => 'forward',
                'comment'          => 'captive_block_internet',
                'src-address-list' => self::BLOCKED_USERS_LIST,
                'dst-address-list' => '!' . self::WALLED_GARDEN_LIST,
                'action'           => 'drop',
                'src-address'      => '',
                'dst-address'      => '',
                'protocol'         => '',
                'dst-port'         => '',
            ],
        ];

        $this->setFilterRules($rules);
    }


    private function setNat(array $content): void
    {
        $section = '/ip/firewall/nat';

        $attrs = [
            'chain',
            'action',
            'comment',
            'src-address-list',
            'dst-address-list',
            'protocol',
            'dst-port',
            'to-addresses',
            'to-ports',
            'jump-target',
            'dst-address',
            'src-address',
            'out-interface',
        ];

        $remoteSectionList = $this->getSectionList($section, $attrs);

        $remoteList = $this->createIndex($remoteSectionList, $attrs);
        $localList = $this->createIndex($content, $attrs);
        $toRemove = array_diff_key($remoteList, $localList);
        $toAdd = array_diff_key($localList, $remoteList);

        $this->routerOsApi->remove($section, array_column($toRemove, '.id'));
        $this->routerOsApi->add($section, $toAdd);
    }


    private function setFilterRules(array $content): void
    {
        $section = '/ip/firewall/filter';
        $attrs = [
            'chain',
            'comment',
            'src-address-list',
            'dst-address-list',
            'dst-address',
            'action',
            'src-address',
            'dst-port',
            'protocol',
        ];

        $remoteList = $this->createIndex($this->getSectionList($section, $attrs), $attrs);
        $localList = $this->createIndex($content, $attrs);

        $toRemove = array_diff_key($remoteList, $localList);
        $toAdd = array_diff_key($localList, $remoteList);

        $this->routerOsApi->remove($section, array_column($toRemove, '.id'));
        $this->routerOsApi->add($section, $toAdd);
    }

    private function todayInConfigTz(): string
    {
        $tzName = trim((string) ($this->config['timezone'] ?? ''));
        try {
            $tz = new \DateTimeZone(self::normalizeTimezone($tzName ?: date_default_timezone_get()));
        } catch (\Exception $e) {
            $tz = new \DateTimeZone(date_default_timezone_get());
        }

        return (new \DateTime('now', $tz))->format('Y-m-d');
    }

    /**
     * Targeted check for a single prepaid service: does it have a period
     * covering today? Used by the webhook to decide block vs unblock.
     */
    public function hasActivePrepaidPeriod(int $serviceId): bool
    {
        if ($serviceId <= 0) {
            return false;
        }

        $today = $this->todayInConfigTz();

        $periods = $this->ucrmApi->get(
            'prepaid-service-periods',
            [
                'serviceId'   => $serviceId,
                'startDateTo' => $today,
                'endDateFrom' => $today,
                'limit'       => 100,
            ]
        );

        foreach ($periods as $period) {
            if ((int) ($period['serviceId'] ?? 0) === $serviceId) {
                return true;
            }
        }

        return false;
    }

    private function fetchActivePrepaidPeriodServiceIds(): array
    {
        $today = $this->todayInConfigTz();

        $result = [];
        $offset = 0;
        $limit  = 500;

        do {
            $periods = $this->ucrmApi->get(
                'prepaid-service-periods',
                [
                    'startDateTo' => $today,
                    'endDateFrom' => $today,
                    'limit'       => $limit,
                    'offset'      => $offset,
                ]
            );

            foreach ($periods as $period) {
                if (!empty($period['serviceId'])) {
                    $result[$period['serviceId']] = true;
                }
            }

            $offset += $limit;
        } while (count($periods) === $limit);

        return $result;
    }

    private function findPrepaidServicesWithoutActivePeriod(array $activePrepaidServiceIds): array
    {
        // Fetch all prepaid services regardless of status
        $prepaidServices = $this->ucrmApi->get(
            'clients/services',
            [
                'prepaid' => 1,
            ]
        );

        $this->emit('Found ' . count($prepaidServices) . ' prepaid services total', 'info');
        $this->emit('Found ' . count($activePrepaidServiceIds) . ' prepaid services with active periods today', 'info');

        if (empty($prepaidServices)) {
            return [];
        }

        // Return prepaid services that have no active period today.
        // Exclude status=3 (Suspended) only when the service also has no active period
        // — if it has an active period it is already excluded via syncAddressList().
        $result = [];
        foreach ($prepaidServices as $service) {
            $serviceId = $service['id'] ?? null;
            if ($serviceId !== null && !isset($activePrepaidServiceIds[$serviceId])) {
                $result[] = $service;
            }
        }

        return $result;
    }

    private function findServicesToSuspend(): array
    {
        // Get suspended services (status 3)
        $suspendedServices = $this->ucrmApi->get(
            'clients/services',
            [
                'statuses' => [self::SERVICE_STATUS_ACTIVE],
            ]
        );

        // Also get services from archived clients
        try {
            $archivedClients = $this->ucrmApi->get('clients', ['isArchived' => 1]);
            foreach ($archivedClients as $client) {
                $clientId = $client['id'] ?? null;
                if ($clientId) {
                    $clientServices = $this->ucrmApi->get('clients/services', ['clientId' => $clientId]);
                    foreach ($clientServices as $service) {
                        $suspendedServices[] = $service;
                    }
                }
            }
        } catch (\Exception $e) {
            // Continue if archived clients fetch fails
        }

        return $suspendedServices;
    }

    /**
     * Resolves every candidate client's IP(s) from their custom attribute.
     * Bulk-fetches all clients (active + archived) once and caches them.
     *
     * @param int[] $clientIds
     * @return string[]
     */
    private function resolveIpsFromClientAttribute(array $clientIds): array
    {
        if (empty($clientIds)) {
            return [];
        }

        $clientsById = $this->fetchAllClientsById();

        $ipAddresses = [];
        foreach ($clientIds as $clientId) {
            $client = $clientsById[$clientId] ?? null;
            if ($client === null) {
                if ($this->skipCallback) {
                    ($this->skipCallback)((int) $clientId, '#' . $clientId, 'Client record not found');
                }
                continue;
            }

            $ips = $this->getClientIps($client);
            if (empty($ips)) {
                if ($this->skipCallback) {
                    ($this->skipCallback)((int) $clientId, $this->clientLabel($client), 'No valid IP in attribute "' . $this->attributeName . '"');
                }
                continue;
            }

            foreach ($ips as $ip) {
                $ipAddresses[] = $ip;
            }
        }

        return array_values(array_unique($ipAddresses));
    }

    /**
     * @return array<int, array>
     */
    private function fetchAllClientsById(): array
    {
        if ($this->allClientsCache !== null) {
            return $this->allClientsCache;
        }

        $active = $this->ucrmApi->get('clients');
        $archived = [];
        try {
            $archived = $this->ucrmApi->get('clients', ['isArchived' => 1]);
        } catch (\Exception $e) {
            // Continue with active clients only
        }

        $map = [];
        foreach (array_merge($active, $archived) as $client) {
            if (!empty($client['id'])) {
                $map[$client['id']] = $client;
            }
        }

        $this->allClientsCache = $map;
        return $map;
    }

    /**
     * Parses the client's IP custom attribute, which may contain multiple
     * comma-separated IPs (e.g. "10.0.0.5, 10.0.0.6"). Returns all valid IPs.
     *
     * @return string[]
     */
    private function getClientIps(array $client): array
    {
        $raw = $this->getClientAttributeValue($client);
        if ($raw === null || trim($raw) === '') {
            return [];
        }

        $ips = [];
        foreach (explode(',', $raw) as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }
            $ip = $this->stripCidr($part);
            if ($ip !== null && !in_array($ip, $ips, true)) {
                $ips[] = $ip;
            }
        }

        return $ips;
    }

    private function stripCidr(string $value): ?string
    {
        $ip = explode('/', $value)[0];
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : null;
    }

    /**
     * Finds the CLIENT custom attribute matching the configured name and
     * caches its id + key. Returns false if it does not exist.
     */
    private function resolveAttribute(): bool
    {
        if ($this->attributeId !== null) {
            return true;
        }

        try {
            $attributes = $this->ucrmApi->get('custom-attributes');
        } catch (\Exception $e) {
            return false;
        }
        if (! is_array($attributes)) {
            return false;
        }

        $wanted = mb_strtolower(trim($this->attributeName));
        foreach ($attributes as $attr) {
            $type = (string) ($attr['attributeType'] ?? '');
            $name = mb_strtolower(trim((string) ($attr['name'] ?? '')));
            if ($type === 'client' && $name === $wanted) {
                $this->attributeId = (int) $attr['id'];
                $this->attributeKey = (string) ($attr['key'] ?? '');
                return true;
            }
        }

        return false;
    }

    private function getClientAttributeValue(array $client): ?string
    {
        foreach ($client['attributes'] ?? [] as $attr) {
            $matchesId = isset($attr['customAttributeId']) && (int) $attr['customAttributeId'] === $this->attributeId;
            $matchesKey = $this->attributeKey !== '' && ($attr['key'] ?? null) === $this->attributeKey;
            if ($matchesId || $matchesKey) {
                return isset($attr['value']) ? (string) $attr['value'] : null;
            }
        }

        return null;
    }

    /**
     * Best-effort display label for a client (Custom ID when available).
     */
    private function clientLabel(array $client): string
    {
        $id = $client['id'] ?? '?';
        $customId = trim((string) ($client['userIdent'] ?? ''));
        if ($customId !== '') {
            return sprintf('#%s (Custom ID: %s)', $id, $customId);
        }

        return '#' . $id;
    }

    private function syncWalledGarden(array $ipAddresses): void
    {
        $attributes  = ['list', 'address', 'comment'];
        $routerList  = $this->createIndex($this->findAndFilterWalledGardenOnRouter(), $attributes);
        $desiredList = $this->createIndex($this->createWalledGardenEntries($ipAddresses), $attributes);

        $toRemove = array_diff_key($routerList, $desiredList);
        $toAdd    = array_diff_key($desiredList, $routerList);

        $this->removeAddress($toRemove);
        $this->addAddress($toAdd);
    }

    private function createWalledGardenEntries(array $ipAddresses): array
    {
        $rows = [];
        foreach ($ipAddresses as $ip) {
            $rows[] = [
                'list'    => self::WALLED_GARDEN_LIST,
                'address' => $ip,
                'comment' => 'walled_garden',
            ];
        }

        return $rows;
    }

    private function findAndFilterWalledGardenOnRouter(): array
    {
        $filtered = [];
        foreach ($this->routerOsApi->print('/ip/firewall/address-list') as $address) {
            if (
                isset($address['list'])
                && $address['list'] === self::WALLED_GARDEN_LIST
                && array_key_exists('comment', $address)
                && Strings::startsWith($address['comment'], self::COMMENT_SIGNATURE)
            ) {
                $address['comment'] = substr($address['comment'], strlen(self::COMMENT_SIGNATURE));
                $filtered[] = $address;
            }
        }

        return $filtered;
    }

    private function setIpFirewallAddressList(array $ipAddresses): void
    {
        $attributes = ['list', 'address', 'comment'];
        $routerList = $this->createIndex($this->findAndFilterUcrmIpAddressListOnRouter(), $attributes);
        $crmList = $this->createIndex($this->createCrmIpAddressLists($ipAddresses), $attributes);

        $toRemove = array_diff_key($routerList, $crmList);
        $toAdd = array_diff_key($crmList, $routerList);

        $this->emit('Router has ' . count($routerList) . ' entries, CRM has ' . count($crmList) . ' entries', 'info');
        $this->emit('Removing ' . count($toRemove) . ' IPs, Adding ' . count($toAdd) . ' IPs', 'info');

        $this->removeAddress($toRemove);
        $this->addAddress($toAdd);
    }

    private function removeAddress(array $addresses): array
    {
        return $this->routerOsApi->remove('/ip/firewall/address-list', array_column($addresses, '.id'));
    }

    private function addAddress(array $addresses): void
    {
        $this->routerOsApi->add('/ip/firewall/address-list', $addresses);
    }

    private function createIndex(array $arr, array $attrs): array
    {
        $index = [];
        foreach ($arr as $row) {
            $key = $this->createIndexKey($row, $attrs);
            $index[$key] = $row;
        }

        return $index;
    }

    private function createIndexKey(array $item, array $attrs): string
    {
        $res = '';
        foreach ($attrs as $attr) {
            $res .= '_' . (array_key_exists($attr, $item) ? $item[$attr] : '');
        }

        return $res;
    }

    private function createCrmIpAddressLists(array $ipAddresses): array
    {
        $addressListRows = [];
        foreach ($ipAddresses as $ipAddress) {
            $addressListRows[] = [
                'list' => self::BLOCKED_USERS_LIST,
                'address' => $ipAddress,
                'comment' => 'blocked_users',
            ];
        }

        return $addressListRows;
    }

    private function findAndFilterUcrmIpAddressListOnRouter(): array
    {
        $filtered = [];
        foreach ($this->routerOsApi->print('/ip/firewall/address-list') as $address) {
            // Only process entries in BLOCKED_USERS list with ucrm_ comment prefix
            if (
                isset($address['list'])
                && $address['list'] === self::BLOCKED_USERS_LIST
                && array_key_exists('comment', $address)
                && Strings::startsWith($address['comment'], self::COMMENT_SIGNATURE)
            ) {
                $address['comment'] = substr($address['comment'], strlen(self::COMMENT_SIGNATURE));
                $filtered[] = $address;
            }
        }

        return $filtered;
    }

    private function getSectionList(string $section, array $attributes): array
    {
        $data = $this->getRawSectionList($section, $attributes);

        $filtered = [];
        foreach ($data as $row) {
            if (array_key_exists('comment', $row) && Strings::startsWith($row['comment'], self::COMMENT_SIGNATURE)) {
                $row['comment'] = substr($row['comment'], strlen(self::COMMENT_SIGNATURE));
                $filtered[] = $row;
            }
        }

        return $filtered;
    }

    private function getRawSectionList(string $section, array $attributes = []): array
    {
        $result = $this->routerOsApi->print(
            $section,
            empty($attributes) ? [] : ['.proplist' => sprintf('.id,%s', implode(',', $attributes))]
        );

        return is_array($result) ? $result : [];
    }

    private static function normalizeTimezone(string $tz): string
    {
        // Convert "UTC+8", "GMT+8", "UTC+8:30" etc. to "+08:00" which PHP accepts
        if (preg_match('/^(?:UTC|GMT)([+-])(\d{1,2})(?::?(\d{2}))?$/i', $tz, $m)) {
            $sign  = $m[1];
            $hours = str_pad($m[2], 2, '0', STR_PAD_LEFT);
            $mins  = (isset($m[3]) && $m[3] !== '') ? $m[3] : '00';
            return $sign . $hours . ':' . $mins;
        }

        return $tz;
    }

    private function validateConfig(array $config): bool
    {
        $configAttributes = [
            'mikrotikIpAddress',
            'mikrotikUserName',
            'mikrotikPassword',
            'captivePortalIp',
        ];

        foreach ($configAttributes as $configAttribute) {
            if (! array_key_exists($configAttribute, $config)) {
                return false;
            }
        }

        return true;
    }
}
