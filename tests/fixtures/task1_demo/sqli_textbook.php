<?php
// Textbook SQL Injection (Unsanitized $_GET parameter concatenated into mysqli_query)
$id = $_GET['id'];
$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
