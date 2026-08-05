<?php
// Vulnerable BAC: authorization based on cookie
$id = intval($_GET['user_id']);
if ($id == intval($_COOKIE['user_id'])) {
    // show profile
    $q = "SELECT * FROM users WHERE user_id = $id";
    mysqli_query($GLOBALS['___mysqli_ston'], $q);
}
?>