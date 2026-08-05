<?php
// Vulnerable: SSRF via user-controlled URL
$url = $_GET['url'];
$file = file_get_contents($url);
?>