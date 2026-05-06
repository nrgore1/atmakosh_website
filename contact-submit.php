<?php
// Atmakosh contact form handler for Hostinger shared hosting.
// Saves one JSON object per line in a private JSONL file.

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'message' => 'Method not allowed.']);
    exit;
}

function fail($message, $code = 400) {
    http_response_code($code);
    echo json_encode(['ok' => false, 'message' => $message]);
    exit;
}

function clean_text($value, $max = 500) {
    $value = trim((string)$value);
    $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value);
    $value = strip_tags($value);
    if (mb_strlen($value, 'UTF-8') > $max) {
        $value = mb_substr($value, 0, $max, 'UTF-8');
    }
    return $value;
}

// Honeypot: real users never fill this hidden field.
if (!empty($_POST['website'] ?? '')) {
    fail('Submission rejected.', 422);
}

// Timing trap: blocks many instant bot posts.
$startedAt = (int)($_POST['form_started_at'] ?? 0);
if ($startedAt > 0 && (time() - $startedAt) < 3) {
    fail('Please wait a moment before submitting.', 429);
}

$name = clean_text($_POST['name'] ?? '', 120);
$email = clean_text($_POST['email'] ?? '', 160);
$organization = clean_text($_POST['organization'] ?? '', 160);
$interest = clean_text($_POST['interest'] ?? '', 120);
$message = clean_text($_POST['message'] ?? '', 1600);

if ($name === '' || $email === '' || $interest === '' || $message === '') {
    fail('Please complete the required fields.');
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fail('Please enter a valid email address.');
}
if (preg_match('/https?:\/\/|\[url=|<a\s/i', $message)) {
    fail('Links are not allowed in the message field.');
}

$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$userAgent = clean_text($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 300);
$now = time();

// Prefer storage outside public_html. Fallback remains web-blocked by .htaccess.
$privateDir = dirname(__DIR__) . '/atmakosh_private';
if (!is_dir($privateDir) && !@mkdir($privateDir, 0750, true)) {
    $privateDir = __DIR__ . '/protected-data';
    if (!is_dir($privateDir) && !@mkdir($privateDir, 0750, true)) {
        fail('Storage is not available. Please contact site administrator.', 500);
    }
}

// Ensure fallback folder cannot be browsed or downloaded on Apache/LiteSpeed.
$denyFile = $privateDir . '/.htaccess';
if (!file_exists($denyFile)) {
    @file_put_contents($denyFile, "Require all denied\nDeny from all\n");
}

$rateFile = $privateDir . '/rate-limit.json';
$leadFile = $privateDir . '/contact-submissions.jsonl';

// Basic per-IP rate limit: 5 submissions/hour.
$rate = [];
if (file_exists($rateFile)) {
    $decoded = json_decode((string)file_get_contents($rateFile), true);
    if (is_array($decoded)) { $rate = $decoded; }
}
foreach ($rate as $key => $items) {
    $rate[$key] = array_values(array_filter((array)$items, fn($ts) => ($now - (int)$ts) < 3600));
    if (empty($rate[$key])) { unset($rate[$key]); }
}
$ipKey = hash('sha256', $ip);
$attempts = $rate[$ipKey] ?? [];
if (count($attempts) >= 5) {
    fail('Too many submissions. Please try again later.', 429);
}
$attempts[] = $now;
$rate[$ipKey] = $attempts;
@file_put_contents($rateFile, json_encode($rate, JSON_PRETTY_PRINT), LOCK_EX);

$record = [
    'submitted_at' => gmdate('c'),
    'name' => $name,
    'email' => $email,
    'organization' => $organization,
    'interest' => $interest,
    'message' => $message,
    'ip_hash' => $ipKey,
    'user_agent' => $userAgent,
];

$line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
if (@file_put_contents($leadFile, $line, FILE_APPEND | LOCK_EX) === false) {
    fail('Could not save submission. Please contact site administrator.', 500);
}
@chmod($leadFile, 0640);

echo json_encode(['ok' => true, 'message' => 'Thank you. Your inquiry has been received.']);
