<?php

declare(strict_types=1);

/*
 * Copies the shared conformance fixtures into tests/fixtures.
 *
 * The fixtures are owned by the ZevAuth server-SDK contract,
 * https://github.com/zevop/zevauth-sdk/tree/main/spec, and every ZevAuth
 * server library runs the same files. They are vendored here so the test
 * suite runs without that repository. Never edit the copies: change the
 * contract, regenerate there, then sync.
 *
 *     composer sync-fixtures                    # from ../zevauth-sdk
 *     php scripts/sync-fixtures.php /path/to/zevauth-sdk
 */

$sdk = $argv[1] ?? dirname(__DIR__, 2) . '/zevauth-sdk';
$source = rtrim($sdk, '/') . '/spec/fixtures';
$target = dirname(__DIR__) . '/tests/fixtures';

if (!is_dir($source)) {
    fwrite(STDERR, "No fixtures at {$source}. Pass the path to a zevauth-sdk checkout.\n");
    exit(1);
}

$copied = 0;
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS));
foreach ($iterator as $file) {
    /** @var SplFileInfo $file */
    $relative = substr($file->getPathname(), strlen($source) + 1);
    $destination = "{$target}/{$relative}";
    if (!is_dir(dirname($destination))) {
        mkdir(dirname($destination), 0777, true);
    }
    copy($file->getPathname(), $destination);
    $copied++;
}

echo "Copied {$copied} fixture files from {$source}.\n";
