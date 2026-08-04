<?php
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = :user');
$stmt->execute(['user' => $_POST['user']]);
?>
