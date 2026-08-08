<?php

declare(strict_types=1);


namespace ComsatRouterOs\Service;

use RouterOS\Client;
use RouterOS\Query;

class RouterOsApi
{
    /**
     * @var Client|null
     */
    private $client;

    /**
     * @var array
     */
    private $clientConfig;

    public function __construct(array $clientConfig)
    {
        $this->clientConfig = $clientConfig;
    }

    public static function create(array $config): self
    {
        return new self(
            [
                'host' => $config['mikrotikIpAddress'],
                'user' => $config['mikrotikUserName'],
                'pass' => (string) $config['mikrotikPassword'],
            ]
        );
    }

    public function connect(): void
    {
        $this->getClient();
    }

    public function disconnect(): void
    {
        $this->client = null;
    }

    public function print(string $endpoint): array
    {
        return $this->getClient()->write(new Query(sprintf('%s/print', $endpoint)))->read();
    }

    public function remove(string $endpoint, array $ids): array
    {
        if (! $ids) {
            return [];
        }

        $query = (new Query(sprintf('%s/remove', $endpoint)))
            ->add(sprintf('=.id=%s', implode(',', $ids)));

        return $this->getClient()->write($query)->read();
    }

    public function add(string $endpoint, array $sentences, string $commentPrefix = 'ucrm_'): void
    {
        foreach ($sentences as $sentence) {
            $sentence = array_filter($sentence);

            if (
                $commentPrefix
                && $sentence['comment'] ?? false
            ) {
                $sentence['comment'] = sprintf('%s%s', $commentPrefix, $sentence['comment']);
            }

            $query = new Query(sprintf('%s/add', $endpoint));

            foreach ($sentence as $key => $item) {
                $query->add(sprintf('=%s=%s', $key, $item));
            }

            $this->getClient()->write($query)->read();
        }
    }

    public function getClient(): Client
    {
        if ($this->client === null) {
            $this->client = new Client($this->clientConfig);
        }

        return $this->client;
    }
}
