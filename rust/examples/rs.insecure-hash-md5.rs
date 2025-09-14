//! Example code that demonstrates the rs.insecure-hash-md5 rule violation.
//! This code should trigger the security rule.

use md5::{Md5, Digest};
use md2::Md2;
use md4::Md4;
use sha1::Sha1;

fn unsafe_md5_example() {
    /// This function demonstrates unsafe MD5 usage.
    let mut hasher = Md5::new(); // This will trigger the rule
    hasher.update(b"password");
    let result = hasher.finalize();
    println!("MD5 hash: {:x}", result);
}

fn another_unsafe_md5_example() {
    /// Another example of unsafe MD5 usage.
    let data = b"sensitive_data";
    let mut hasher = Md5::new(); // This will trigger the rule
    hasher.update(data);
    let hash = hasher.finalize();
    println!("Hash: {:x}", hash);
}

fn md5_for_file_hash() {
    /// Example using MD5 for file hashing.
    use std::fs;
    
    let file_data = fs::read("important_file.txt").unwrap();
    let mut hasher = Md5::new(); // This will trigger the rule
    hasher.update(&file_data);
    let file_hash = hasher.finalize();
    println!("File hash: {:x}", file_hash);
}

fn md5_in_loop() {
    /// Example using MD5 in a loop.
    let passwords = vec!["pass1", "pass2", "pass3"];
    let mut hashes = Vec::new();
    
    for password in passwords {
        let mut hasher = Md5::new(); // This will trigger the rule
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        hashes.push(format!("{:x}", hash));
    }
    
    for hash in hashes {
        println!("Password hash: {}", hash);
    }
}

fn md5_with_salt() {
    /// Example using MD5 with salt (still unsafe).
    let password = "user_password";
    let salt = "random_salt";
    let combined = format!("{}{}", password, salt);
    
    let mut hasher = Md5::new(); // This will trigger the rule
    hasher.update(combined.as_bytes());
    let hash = hasher.finalize();
    println!("Salted hash: {:x}", hash);
}

fn md2_example() {
    /// Example using MD2 (also insecure).
    let mut hasher = Md2::new(); // This will trigger the rule
    hasher.update(b"data");
    let result = hasher.finalize();
    println!("MD2 hash: {:x}", result);
}

fn md4_example() {
    /// Example using MD4 (also insecure).
    let mut hasher = Md4::new(); // This will trigger the rule
    hasher.update(b"data");
    let result = hasher.finalize();
    println!("MD4 hash: {:x}", result);
}

fn sha1_example() {
    /// Example using SHA-1 (also insecure).
    let mut hasher = Sha1::new(); // This will trigger the rule
    hasher.update(b"data");
    let result = hasher.finalize();
    println!("SHA-1 hash: {:x}", result);
}

fn multiple_insecure_hashes() {
    /// Example using multiple insecure hash functions.
    let data = b"important_data";
    
    let mut md5_hasher = Md5::new(); // This will trigger the rule
    md5_hasher.update(data);
    let md5_hash = md5_hasher.finalize();
    
    let mut sha1_hasher = Sha1::new(); // This will trigger the rule
    sha1_hasher.update(data);
    let sha1_hash = sha1_hasher.finalize();
    
    println!("MD5: {:x}", md5_hash);
    println!("SHA-1: {:x}", sha1_hash);
}

fn main() {
    unsafe_md5_example();
    another_unsafe_md5_example();
    md5_for_file_hash();
    md5_in_loop();
    md5_with_salt();
    md2_example();
    md4_example();
    sha1_example();
    multiple_insecure_hashes();
}
