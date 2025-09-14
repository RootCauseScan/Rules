package rust.security

# Deny unwrap() usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "MethodCall"
    node.method == "unwrap"
    msg := "Unsafe unwrap() usage detected. Use proper error handling with match, if let, or ? operator."
}

# Deny expect() usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "MethodCall"
    node.method == "expect"
    msg := "Unsafe expect() usage detected. Use proper error handling with match, if let, or ? operator."
}

# Deny panic! macro usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Macro"
    node.name == "panic"
    msg := "panic! macro usage detected. Use proper error handling and return Result or Option types."
}

# Deny unsafe blocks
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "UnsafeBlock"
    msg := "Unsafe block detected. Ensure proper safety documentation and consider safe alternatives."
}

# Deny unsafe functions
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Function"
    node.unsafe == true
    msg := "Unsafe function detected. Ensure proper safety documentation and consider safe alternatives."
}

# Deny unsafe traits
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Trait"
    node.unsafe == true
    msg := "Unsafe trait detected. Ensure proper safety documentation and consider safe alternatives."
}

# Deny unsafe impl blocks
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Impl"
    node.unsafe == true
    msg := "Unsafe impl block detected. Ensure proper safety documentation and consider safe alternatives."
}

# Deny raw pointers
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "RawPointer"
    msg := "Raw pointer usage detected. Use references, Box, Rc, or Arc instead."
}

# Deny MD5 usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Path"
    node.segments[_] == "Md5"
    msg := "Weak MD5 hash function detected. Use SHA-256 or stronger hash functions for security purposes."
}

# Deny MD2 usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Path"
    node.segments[_] == "Md2"
    msg := "Weak MD2 hash function detected. Use SHA-256 or stronger hash functions for security purposes."
}

# Deny MD4 usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Path"
    node.segments[_] == "Md4"
    msg := "Weak MD4 hash function detected. Use SHA-256 or stronger hash functions for security purposes."
}

# Deny SHA-1 usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Path"
    node.segments[_] == "Sha1"
    msg := "Weak SHA-1 hash function detected. Use SHA-256 or stronger hash functions for security purposes."
}

# Deny std::mem::forget usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Path"
    node.segments[0] == "std"
    node.segments[1] == "mem"
    node.segments[2] == "forget"
    msg := "std::mem::forget usage detected. Use proper RAII patterns and let values be dropped naturally."
}

# Deny std::mem::drop usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Path"
    node.segments[0] == "std"
    node.segments[1] == "mem"
    node.segments[2] == "drop"
    msg := "Manual std::mem::drop usage detected. Let values be dropped naturally at the end of their scope."
}

# Deny String::from_raw_parts usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Path"
    node.segments[0] == "String"
    node.segments[1] == "from_raw_parts"
    msg := "Unsafe String::from_raw_parts usage detected. Use safe string operations and proper UTF-8 validation."
}

# Deny std::str::from_utf8_unchecked usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Path"
    node.segments[0] == "std"
    node.segments[1] == "str"
    node.segments[2] == "from_utf8_unchecked"
    msg := "Unsafe std::str::from_utf8_unchecked usage detected. Use safe string operations and proper UTF-8 validation."
}

# Deny CString::from_raw usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Path"
    node.segments[0] == "CString"
    node.segments[1] == "from_raw"
    msg := "Unsafe CString::from_raw usage detected. Use safe string operations and proper UTF-8 validation."
}

# Deny std::mem::transmute usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Path"
    node.segments[0] == "std"
    node.segments[1] == "mem"
    node.segments[2] == "transmute"
    msg := "Unsafe std::mem::transmute usage detected. Use safe type conversions or ensure proper safety documentation."
}

# Deny unreachable! macro usage
deny[msg] {
    input.file_type == "rust"
    node := input.nodes[_]
    node.type == "Macro"
    node.name == "unreachable"
    msg := "unreachable! macro usage detected. Use proper control flow or handle all possible cases."
}

# Deny TODO comments
deny[msg] {
    input.file_type == "rust"
    comment := input.comments[_]
    contains(comment.text, "TODO")
    msg := "TODO comment detected. Resolve TODO items or create proper issue tracking."
}

# Deny FIXME comments
deny[msg] {
    input.file_type == "rust"
    comment := input.comments[_]
    contains(comment.text, "FIXME")
    msg := "FIXME comment detected. Resolve FIXME items or create proper issue tracking."
}

# Deny XXX comments
deny[msg] {
    input.file_type == "rust"
    comment := input.comments[_]
    contains(comment.text, "XXX")
    msg := "XXX comment detected. Resolve XXX items or create proper issue tracking."
}
