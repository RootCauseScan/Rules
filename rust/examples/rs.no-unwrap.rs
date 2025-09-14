//! Example code that demonstrates the rs.no-unwrap rule violation.
//! This code should trigger the security rule.

use std::collections::HashMap;

fn unsafe_unwrap_example() {
    /// This function demonstrates unsafe unwrap usage.
    let option_value: Option<i32> = Some(42);
    let value = option_value.unwrap(); // This will trigger the rule
    println!("Value: {}", value);
}

fn another_unsafe_unwrap_example() {
    /// Another example of unsafe unwrap usage.
    let result: Result<String, &str> = Ok("Hello".to_string());
    let message = result.unwrap(); // This will trigger the rule
    println!("Message: {}", message);
}

fn unwrap_in_loop() {
    /// Example using unwrap in a loop.
    let numbers = vec![Some(1), Some(2), Some(3)];
    
    for num in numbers {
        let value = num.unwrap(); // This will trigger the rule
        println!("Number: {}", value);
    }
}

fn unwrap_with_collections() {
    /// Example using unwrap with collections.
    let mut map = HashMap::new();
    map.insert("key", "value");
    
    let value = map.get("key").unwrap(); // This will trigger the rule
    println!("Value: {}", value);
}

fn unwrap_in_function() -> i32 {
    /// Example using unwrap in a function return.
    let option_value: Option<i32> = Some(100);
    option_value.unwrap() // This will trigger the rule
}

fn unwrap_with_chain() {
    /// Example using unwrap in a method chain.
    let text = "Hello, World!";
    let first_char = text.chars().next().unwrap(); // This will trigger the rule
    println!("First character: {}", first_char);
}

fn unwrap_with_parsing() {
    /// Example using unwrap with parsing.
    let number_str = "42";
    let number = number_str.parse::<i32>().unwrap(); // This will trigger the rule
    println!("Parsed number: {}", number);
}

fn unwrap_with_file_operations() {
    /// Example using unwrap with file operations.
    use std::fs;
    
    let content = fs::read_to_string("config.txt").unwrap(); // This will trigger the rule
    println!("File content: {}", content);
}

fn main() {
    unsafe_unwrap_example();
    another_unsafe_unwrap_example();
    unwrap_in_loop();
    unwrap_with_collections();
    let result = unwrap_in_function();
    println!("Function result: {}", result);
    unwrap_with_chain();
    unwrap_with_parsing();
    unwrap_with_file_operations();
}
