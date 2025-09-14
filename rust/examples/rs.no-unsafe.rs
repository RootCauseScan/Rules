//! Example code that demonstrates the rs.no-unsafe rule violation.
//! This code should trigger the security rule.

use std::ptr;

fn unsafe_block_example() {
    /// This function demonstrates unsafe block usage.
    let x = 5;
    let y = &x as *const i32;
    
    unsafe {
        println!("Value: {}", *y); // This will trigger the rule
    }
}

fn unsafe_function_example() {
    /// Example of unsafe function usage.
    let mut data = vec![1, 2, 3, 4, 5];
    let ptr = data.as_mut_ptr();
    
    unsafe {
        *ptr = 10; // This will trigger the rule
    }
}

fn unsafe_trait_example() {
    /// Example using unsafe trait.
    unsafe trait UnsafeTrait {
        fn dangerous_method(&self);
    }
    
    struct UnsafeStruct;
    
    unsafe impl UnsafeTrait for UnsafeStruct {
        fn dangerous_method(&self) {
            println!("This is dangerous!");
        }
    }
}

fn unsafe_with_raw_pointers() {
    /// Example using unsafe with raw pointers.
    let x = 42;
    let raw_ptr = &x as *const i32;
    
    unsafe {
        let value = *raw_ptr; // This will trigger the rule
        println!("Value from raw pointer: {}", value);
    }
}

fn unsafe_with_memory_operations() {
    /// Example using unsafe memory operations.
    let mut data = [1, 2, 3, 4, 5];
    let ptr = data.as_mut_ptr();
    
    unsafe {
        ptr::write(ptr, 10); // This will trigger the rule
    }
}

fn unsafe_with_ffi() {
    /// Example using unsafe with FFI.
    extern "C" {
        fn printf(format: *const i8, ...);
    }
    
    unsafe {
        let format = b"Hello, World!\n\0" as *const u8 as *const i8;
        printf(format); // This will trigger the rule
    }
}

fn unsafe_with_transmute() {
    /// Example using unsafe transmute.
    let x: i32 = 42;
    
    unsafe {
        let y: f32 = std::mem::transmute(x); // This will trigger the rule
        println!("Transmuted value: {}", y);
    }
}

fn unsafe_with_union() {
    /// Example using unsafe with union.
    union MyUnion {
        i: i32,
        f: f32,
    }
    
    let u = MyUnion { i: 42 };
    
    unsafe {
        let value = u.i; // This will trigger the rule
        println!("Union value: {}", value);
    }
}

fn unsafe_with_static_mut() {
    /// Example using unsafe with static mut.
    static mut COUNTER: i32 = 0;
    
    unsafe {
        COUNTER += 1; // This will trigger the rule
        println!("Counter: {}", COUNTER);
    }
}

fn main() {
    unsafe_block_example();
    unsafe_function_example();
    unsafe_trait_example();
    unsafe_with_raw_pointers();
    unsafe_with_memory_operations();
    unsafe_with_ffi();
    unsafe_with_transmute();
    unsafe_with_union();
    unsafe_with_static_mut();
}
