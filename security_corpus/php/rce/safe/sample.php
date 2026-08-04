<?php
// Safe output without command execution
$val = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "Hello " . $val;
?>
