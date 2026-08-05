<?php
// Vulnerable: unserialize on POST data
$data = unserialize($_POST['payload']);
?>