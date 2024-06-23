<?php
// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Include database configuration
    include 'db_config.php';

    // Get form data
    $email = $_POST['email'];
    $fullname = $_POST['fullname'];
    $password = $_POST['password'];

    // Validate form data
    if (empty($email) || empty($fullname) || empty($password)) {
        echo "All fields are required";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "Invalid email format";
    } else {
        // Hash the password
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Insert user into database
        $sql = "INSERT INTO users (email, fullname, password) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sss", $email, $fullname, $hashed_password);

        if ($stmt->execute()) {
            echo "User registered successfully";
            header("location: index.html");
        } else {
            echo "Error: " . $stmt->error;
        }

        $stmt->close();
    }

    // Close database connection
    $conn->close();
}
?>
