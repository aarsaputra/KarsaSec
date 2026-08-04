<?php
$id = $_GET['id'];
$pdo->query("SELECT * FROM items WHERE id = " . $id);
?>
