# CWE-787: Out-of-Bounds Write

## What is the weakness?

[CWE-787](https://cwe.mitre.org/data/definitions/787.html) describes a program that writes data past the end, or before the beginning, of the buffer it is supposed to write into. The extra bytes overwrite adjacent memory, which may hold other variables, control data, or saved return addresses.

Out-of-bounds writes are among the most serious memory-safety bugs. Depending on what gets overwritten, the result can be a crash, corrupted program state, a changed security decision, or, if an attacker controls the input, arbitrary code execution.

## The vulnerable code

`programa.c`:

```c
#include <stdio.h>

int main() {
  int cookie;
  char buf[4];

  printf("buf: %08p cookie: %08p\n", &buf, &cookie);

  gets(buf);

  if (cookie == 0x41424344) {
    printf("\nGanaste!\n");
  } else {
    printf("\nPerdiste!\n");
  }
}
```

### Why it is vulnerable

- `buf` holds only 4 bytes.
- `gets()` reads from standard input until a newline or end of file, and it has no way to know the size of `buf`. Any input longer than 3 characters (plus the terminating `'\0'`) is written past the end of `buf`.
- On the stack, `cookie` is declared next to `buf`. Depending on the compiler and layout, the bytes that overflow `buf` can land on `cookie`, changing the value the `if` tests.

So the program's "cookie" check can be bypassed simply by sending more input than `buf` can hold. The program prints the addresses of `buf` and `cookie` at startup, which makes it easy to see where the overflow goes; this is a teaching example of the bug.

`gets()` was removed from the C11 standard for exactly this reason. Most modern toolchains warn about it or refuse to link it.

## The fix

Use a function that is told the size of the destination buffer and stops writing when it is full. `fgets()` does this:

```c
#include <stdio.h>

int main() {
  int cookie;
  char buf[4];

  printf("buf: %08p cookie: %08p\n", (void *)&buf, (void *)&cookie);

  if (fgets(buf, sizeof(buf), stdin) == NULL) {
    return 1;
  }

  if (cookie == 0x41424344) {
    printf("\nGanaste!\n");
  } else {
    printf("\nPerdiste!\n");
  }
}
```

Notes on the fix:

- `fgets(buf, sizeof(buf), stdin)` writes at most `sizeof(buf) - 1` characters and always adds a terminating `'\0'`, so it cannot write past the end of `buf`.
- Any input longer than the buffer is truncated instead of overflowing. The remaining input stays in the stdin buffer; if you need to discard it, read and throw it away until a newline.
- The `%08p` format is not standard for pointers; `%p` is the portable choice, and casting the pointers to `void *` avoids undefined behavior. The fixed version uses `(void *)` casts for that reason.
- Checking `fgets()`'s return value handles end-of-file and read errors.

The `cookie` variable is still uninitialized in both versions, so the `if` result is undefined behavior on its own. This is a separate issue from the overflow, but it is worth fixing in real code (for example, `int cookie = 0;`).

## Verifying the bug and the fix

With GCC or Clang, AddressSanitizer detects the out-of-bounds write and reports it with a stack trace:

```sh
gcc -g -fsanitize=address -o programa programa.c
./programa
```

Then type a line longer than 3 characters. The vulnerable version should report a `stack-buffer-overflow` on `buf`. The fixed version should run without a report.

## Related weaknesses

- [CWE-787](https://cwe.mitre.org/data/definitions/787.html): Out-of-Bounds Write (this document)
- [CWE-125](https://cwe.mitre.org/data/definitions/125.html): Out-of-Bounds Read
- [CWE-120](https://cwe.mitre.org/data/definitions/120.html): Buffer Copy without Checking Size of Input (Classic Buffer Overflow)
- [CWE-242](https://cwe.mitre.org/data/definitions/242.html): Use of Inherently Dangerous Function (`gets`)
