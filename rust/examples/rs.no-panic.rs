//! Example code that demonstrates the rs.no-panic rule violation.
//! This code should trigger the security rule.

fn panic_example() {
    /// This function demonstrates panic! usage.
    let condition = false;
    if !condition {
        panic!("Something went wrong!"); // This will trigger the rule
    }
}

fn panic_with_message() {
    /// Example of panic! with a message.
    let value = 42;
    if value < 0 {
        panic!("Value cannot be negative: {}", value); // This will trigger the rule
    }
}

fn panic_in_loop() {
    /// Example using panic! in a loop.
    let numbers = vec![1, 2, 3, 4, 5];
    
    for num in numbers {
        if num < 0 {
            panic!("Negative number found: {}", num); // This will trigger the rule
        }
    }
}

fn panic_with_format() {
    /// Example using panic! with format string.
    let name = "John";
    let age = 25;
    
    if age < 18 {
        panic!("User {} is underage: {}", name, age); // This will trigger the rule
    }
}

fn panic_in_function() {
    /// Example using panic! in a function.
    let result = divide(10, 0);
    println!("Result: {}", result);
}

fn divide(a: i32, b: i32) -> i32 {
    if b == 0 {
        panic!("Division by zero!"); // This will trigger the rule
    }
    a / b
}

fn panic_with_assertion() {
    /// Example using panic! with assertion-like behavior.
    let x = 5;
    let y = 10;
    
    if x > y {
        panic!("x ({}) should not be greater than y ({})", x, y); // This will trigger the rule
    }
}

fn panic_with_unreachable() {
    /// Example using panic! with unreachable code.
    let value = 42;
    
    match value {
        0 => println!("Zero"),
        1 => println!("One"),
        _ => panic!("Unexpected value: {}", value), // This will trigger the rule
    }
}

fn panic_with_error_handling() {
    /// Example using panic! in error handling.
    let result: Result<i32, &str> = Err("Something went wrong");
    
    match result {
        Ok(value) => println!("Success: {}", value),
        Err(error) => panic!("Error occurred: {}", error), // This will trigger the rule
    }
}

fn panic_with_validation() {
    /// Example using panic! for validation.
    let email = "invalid-email";
    
    if !email.contains('@') {
        panic!("Invalid email format: {}", email); // This will trigger the rule
    }
}

fn panic_with_file_operations() {
    /// Example using panic! with file operations.
    use std::fs;
    
    let content = fs::read_to_string("config.txt");
    
    match content {
        Ok(data) => println!("File content: {}", data),
        Err(_) => panic!("Failed to read config file!"), // This will trigger the rule
    }
}

fn panic_with_network_operations() {
    /// Example using panic! with network operations.
    let url = "http://example.com";
    
    // Simulating network request
    let response = simulate_network_request(url);
    
    if response.is_err() {
        panic!("Network request failed to {}", url); // This will trigger the rule
    }
}

fn simulate_network_request(_url: &str) -> Result<String, &'static str> {
    Err("Network error")
}

fn main() {
    panic_example();
    panic_with_message();
    panic_in_loop();
    panic_with_format();
    panic_in_function();
    panic_with_assertion();
    panic_with_unreachable();
    panic_with_error_handling();
    panic_with_validation();
    panic_with_file_operations();
    panic_with_network_operations();
}
