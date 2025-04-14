<?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST["username"];
    $password = $_POST["password"];

    // Connect to your MySQL database
    $conn = new mysqli("localhost", "id21437603_tedy", "L1u2c3k4y5@", "id21437603_tedy");

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    $query = "SELECT * FROM users WHERE username = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 1) {
        $row = $result->fetch_assoc();

        if (password_verify($password, $row["password"])) {
            $_SESSION["username"] = $username;
            header("Location: index2.html");
        } else {
            echo "Incorrect password. <a href='login.html'>Try again</a>.";
        }
    } else {
        echo "User not found. <a href='register.html'>Register here</a>.";
    }

    $conn->close();
}
?>

