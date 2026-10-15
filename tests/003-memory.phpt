--TEST--
CURLOPT_OPENSOCKETFUNCTION: memory stays flat in long-running processes
--EXTENSIONS--
curl
curl_hardening
--FILE--
<?php
/* In a worker whose whole life is a single request, what the extension keeps
 * for a handle must go as soon as nothing uses it any more -- not at request
 * shutdown. */
const ITERATIONS = 5000;
const LIMIT = 64 * 1024;

function measure(string $label, callable $iteration, bool $collectEach = false): void {
    $iteration(0);                              // warm-up: allocator, tables
    gc_collect_cycles();
    $before = memory_get_usage();
    for ($i = 1; $i <= ITERATIONS; $i++) {
        $iteration($i);
        if ($collectEach) {
            gc_collect_cycles();
        }
    }
    gc_collect_cycles();
    $growth = memory_get_usage() - $before;
    printf("%-44s %s\n", $label, $growth < LIMIT ? 'flat' : "GREW by {$growth} bytes");
}

$guard = fn (CurlHandle $h, int $p, CurlSocketAddress $a): ?CurlSocket => null;

measure('a new handle per job', function () use ($guard) {
    $ch = curl_init('http://127.0.0.1:1/');
    curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, $guard);
});

$pool = [];
for ($i = 0; $i < 50; $i++) {
    $pool[] = curl_init('http://127.0.0.1:1/');
}
measure('a reused pool, reset and set before each job', function (int $i) use ($pool, $guard) {
    curl_reset($pool[$i % 50]);
    curl_setopt($pool[$i % 50], CURLOPT_OPENSOCKETFUNCTION, $guard);
});

measure('copies and clones of a filtered handle', function () use ($guard) {
    $ch = curl_init('http://127.0.0.1:1/');
    curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, $guard);
    $copy = curl_copy_handle($ch);
    $clone = clone $copy;
});

/* Only the cycle collector reclaims these. Collecting once at the end would
 * measure the collector's own buffers, sized for thousands of live cycles and
 * never shrunk, rather than anything the extension keeps. */
measure('a callback capturing its own handle', function () {
    $ch = curl_init('http://127.0.0.1:1/');
    curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function () use ($ch): ?CurlSocket {
        return curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) !== '' ? null : new CurlSocket();
    });
}, collectEach: true);

echo "Done\n";
?>
--EXPECT--
a new handle per job                         flat
a reused pool, reset and set before each job flat
copies and clones of a filtered handle       flat
a callback capturing its own handle          flat
Done
