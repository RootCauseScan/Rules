#!/usr/bin/env python3
"""
Example code that demonstrates the py.pickle-load rule violation.
This code should trigger the security rule.
"""

import pickle
import io

def unsafe_pickle_load_example():
    """This function demonstrates unsafe pickle.load usage."""
    with open('data.pkl', 'rb') as f:
        data = pickle.load(f)  # This will trigger the rule
    return data

def another_unsafe_pickle_example():
    """Another example of unsafe pickle usage."""
    file_obj = open('user_data.pkl', 'rb')
    user_data = pickle.load(file_obj)  # This will trigger the rule
    file_obj.close()
    return user_data

def unsafe_pickle_loads_example():
    """Example using pickle.loads with untrusted data."""
    serialized_data = b'\x80\x03]q\x00(K\x01K\x02K\x03e.'
    data = pickle.loads(serialized_data)  # This will trigger the rule
    return data

def complex_pickle_example():
    """Complex example with multiple pickle operations."""
    files = ['config.pkl', 'settings.pkl', 'cache.pkl']
    results = []
    
    for filename in files:
        with open(filename, 'rb') as f:
            data = pickle.load(f)  # This will trigger the rule
            results.append(data)
    
    return results

def pickle_with_io_example():
    """Example using pickle with StringIO/BytesIO."""
    import io
    
    # Simulating untrusted data
    untrusted_data = b'pickle_data_here'
    buffer = io.BytesIO(untrusted_data)
    data = pickle.load(buffer)  # This will trigger the rule
    return data

if __name__ == "__main__":
    unsafe_pickle_load_example()
    another_unsafe_pickle_example()
    unsafe_pickle_loads_example()
    complex_pickle_example()
    pickle_with_io_example()
