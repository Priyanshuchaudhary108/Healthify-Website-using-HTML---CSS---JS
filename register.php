<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = $_POST["name"];
    $email = $_POST["email"];
    $username = $_POST["username"];
    $password = $_POST["password"];
    $confirm_password = $_POST["confirm_password"];

    // Verify that the password and confirm_password match
    if ($password !== $confirm_password) {
        echo "Passwords do not match. Please try again.";
    } else {
        $password = password_hash($password, PASSWORD_BCRYPT);

        // Connect to your MySQL database
        $conn = new mysqli("localhost", "id21437603_tedy", "L1u2c3k4y5@", "id21437603_tedy");

        if ($conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }

        // Check if the username already exists
        $check_query = "SELECT * FROM users WHERE username = ?";
        $stmt = $conn->prepare($check_query);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            echo "Username already exists. Please choose a different one.";
        } else {
            // Insert the new user into the database
            $insert_query = "INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)";
            $stmt = $conn->prepare($insert_query);
            $stmt->bind_param("ssss", $name, $email, $username, $password);

            if ($stmt->execute()) {
                // Registration successful, redirect to the dashboard page
                session_start();
                $_SESSION["username"] = $username;
                header("Location: index2.html");
            } else {
                echo "Registration failed. Please try again.";
            }
        }

        $conn->close();
    }
}
?>
