<?php
// Vulnerable: Unsanitized $_GET parameter in include
$file = $_GET['file'];
include($file);
?>
