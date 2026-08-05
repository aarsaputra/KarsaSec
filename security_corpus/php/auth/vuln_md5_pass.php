<?php
// Vulnerable: MD5 used for password hashing
$password = $_POST['password'];
$hash = md5($password);
?>