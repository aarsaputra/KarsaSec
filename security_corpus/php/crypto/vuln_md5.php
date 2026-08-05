<?php
// Vulnerable: MD5 used for password hashing
$password = $_POST['password'];
$h = md5($password);
?>