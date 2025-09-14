package python.security

# Deny unsafe eval usage
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.id == "eval"
    msg := "Unsafe eval() usage detected. Use ast.literal_eval() or other safe alternatives."
}

# Deny unsafe exec usage
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.id == "exec"
    msg := "Unsafe exec() usage detected. Avoid dynamic code execution with untrusted input."
}

# Deny pickle.load usage
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "load"
    node.func.value.value.id == "pickle"
    msg := "Unsafe pickle.load() usage detected. Use json.loads() or other safe deserialization methods."
}

# Deny pickle.loads usage
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "loads"
    node.func.value.value.id == "pickle"
    msg := "Unsafe pickle.loads() usage detected. Use json.loads() or other safe deserialization methods."
}

# Deny subprocess with shell=True
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "run"
    node.func.value.value.id == "subprocess"
    keyword := node.keywords[_]
    keyword.arg == "shell"
    keyword.value.value == true
    msg := "Unsafe subprocess.run() with shell=True detected. Use shell=False and pass arguments as a list."
}

# Deny subprocess.call with shell=True
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "call"
    node.func.value.value.id == "subprocess"
    keyword := node.keywords[_]
    keyword.arg == "shell"
    keyword.value.value == true
    msg := "Unsafe subprocess.call() with shell=True detected. Use shell=False and pass arguments as a list."
}

# Deny subprocess.Popen with shell=True
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "Popen"
    node.func.value.value.id == "subprocess"
    keyword := node.keywords[_]
    keyword.arg == "shell"
    keyword.value.value == true
    msg := "Unsafe subprocess.Popen() with shell=True detected. Use shell=False and pass arguments as a list."
}

# Deny yaml.load usage
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "load"
    node.func.value.value.id == "yaml"
    msg := "Unsafe yaml.load() usage detected. Use yaml.safe_load() instead."
}

# Deny MD5 usage
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "md5"
    node.func.value.value.id == "hashlib"
    msg := "Weak MD5 hash function detected. Use SHA-256 or stronger hash functions for security purposes."
}

# Deny SHA-1 usage
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "sha1"
    node.func.value.value.id == "hashlib"
    msg := "Weak SHA-1 hash function detected. Use SHA-256 or stronger hash functions for security purposes."
}

# Deny requests with verify=False
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "get"
    node.func.value.value.id == "requests"
    keyword := node.keywords[_]
    keyword.arg == "verify"
    keyword.value.value == false
    msg := "SSL verification disabled in requests.get(). Always use verify=True or provide proper certificate validation."
}

# Deny requests.post with verify=False
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "post"
    node.func.value.value.id == "requests"
    keyword := node.keywords[_]
    keyword.arg == "verify"
    keyword.value.value == false
    msg := "SSL verification disabled in requests.post(). Always use verify=True or provide proper certificate validation."
}

# Deny tempfile.mktemp usage
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "mktemp"
    node.func.value.value.id == "tempfile"
    msg := "Unsafe tempfile.mktemp() usage detected. Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead."
}

# Deny os.tmpnam usage
deny[msg] {
    input.file_type == "python"
    node := input.nodes[_]
    node.type == "Call"
    node.func.value.attr == "tmpnam"
    node.func.value.value.id == "os"
    msg := "Unsafe os.tmpnam() usage detected. Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead."
}
