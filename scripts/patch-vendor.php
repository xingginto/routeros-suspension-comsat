<?php
/**
 * Patches evilfreelancer/routeros-api-php's ResourceStream::read() to loop until the
 * full requested length is actually read from the socket.
 *
 * Why: fread() is not guaranteed to return all requested bytes in a single call over a
 * network stream - it may return fewer bytes if the data arrived in multiple TCP segments.
 * The upstream library trusts a single fread() call, which desyncs the RouterOS API word
 * parser and throws a spurious "Error reading N bytes" on an otherwise healthy connection.
 * This was confirmed to cause intermittent sync failures against a live MikroTik device,
 * especially on larger multi-row /print responses (e.g. walled garden / address-list sync).
 *
 * This script is idempotent and safe to run on every `composer install`/`composer update`,
 * since vendor/ is not committed to git and would otherwise lose this fix whenever
 * dependencies are reinstalled.
 */

declare(strict_types=1);

$target = __DIR__ . '/../vendor/evilfreelancer/routeros-api-php/src/Streams/ResourceStream.php';

if (! file_exists($target)) {
    fwrite(STDERR, "[patch-vendor] Skipped: $target not found (vendor not installed yet?)\n");
    exit(0);
}

$contents = file_get_contents($target);
$marker = 'network stream - it may return fewer bytes';

if (strpos($contents, $marker) !== false) {
    echo "[patch-vendor] ResourceStream::read() already patched, nothing to do.\n";
    exit(0);
}

$search = <<<'PHP'
    public function read(int $length): string
    {
        if ($length <= 0) {
            throw new \InvalidArgumentException('Cannot read zero ot negative count of bytes from a stream');
        }

        // TODO: Ignore errors here, but why?
        $result = @fread($this->stream, $length);

        if (false === $result) {
            throw new StreamException("Error reading $length bytes");
        }

        return $result;
    }
PHP;

$replace = <<<'PHP'
    public function read(int $length): string
    {
        if ($length <= 0) {
            throw new \InvalidArgumentException('Cannot read zero ot negative count of bytes from a stream');
        }

        // fread() is not guaranteed to return all $length bytes in a single call over a
        // network stream - it may return fewer bytes if the data arrived in multiple TCP
        // segments. Looping here avoids desyncing the RouterOS API word parser, which
        // otherwise surfaces as a spurious "Error reading N bytes" on an otherwise healthy
        // connection (observed especially on larger multi-row /print responses).
        $buffer = '';
        $remaining = $length;

        while ($remaining > 0) {
            // TODO: Ignore errors here, but why?
            $chunk = @fread($this->stream, $remaining);

            if (false === $chunk || '' === $chunk) {
                throw new StreamException("Error reading $length bytes");
            }

            $buffer .= $chunk;
            $remaining -= strlen($chunk);
        }

        return $buffer;
    }
PHP;

if (strpos($contents, $search) === false) {
    fwrite(STDERR, "[patch-vendor] WARNING: expected unpatched read() body not found in $target. " .
        "The vendored library version may have changed - please review manually.\n");
    exit(0);
}

$contents = str_replace($search, $replace, $contents);
file_put_contents($target, $contents);

echo "[patch-vendor] Patched ResourceStream::read() in $target\n";
