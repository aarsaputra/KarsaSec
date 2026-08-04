<?php
$user = $_POST['user'];
$res = mysqli_query($conn, "SELECT * FROM users WHERE username = '$user'");
?>
