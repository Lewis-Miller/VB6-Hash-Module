# VB6 Hash Module

A clean and lightweight hashing module for Visual Basic 6.

### Supported Algorithms:
- MD5
- SHA1
- SHA256, SHA384, SHA512
- HMAC-SHA256, HMAC-SHA384, HMAC-SHA512

### Usage Examples:

```vb
Debug.Print HashString("hello", HASH_SHA256)

Debug.Print HashFile("C:\test.txt", HASH_SHA512)

Debug.Print HashString("test", HASH_HMACSHA256, "mysecretkey")
```

Simple, fast, and works on Windows Vista and newer.
