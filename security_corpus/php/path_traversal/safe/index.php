<?php
// Safe: Whitelisted file map
$allowed = ['home' => 'home.php', 'about' => 'about.php'];
$page = $_GET['page'] ?? 'home';
if (array_key_exists($page, $allowed)) {
    include($allowed[$page]);
}
?>
