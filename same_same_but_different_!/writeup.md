# Same Same But Different! — Writeup

> Category: **pwn** — Tag: **format-string**
> Flag: `Securinets{s4m3_5truct_r30rd3r3d_bug_st1ll_th3r3}`

The "v2" of [Rootstar Games](../rootstar_games): same bug, same idea, but
the challenge author reordered the `Account` struct and changed the target
string, precisely to prove the point in the flavor text — *"same struct,
same bad habits."*

## 1. What changed vs. Rootstar Games

```c
// Rootstar Games (v1):            // Same Same But Different (v2):
typedef struct Account{            typedef struct Account{
    char role[67];                     char username[67];
    char username[67];                 char password[67];
    char password[67];                 char role[67];
}Account;                          }Account;
#define DEFAULT_ROLE "Developer"   #define DEFAULT_ROLE "Dev"
```

The struct fields got **reordered** (`role` moved from first to last), and
the default role string is now `"Dev"` instead of `"Developer"`. The win
check also changed slightly:

```c
char isAdmin[] = "admin";
...
if (strcmp(account->role, isAdmin) == 0)
    showTopSecretAssest();     // system("cat flag")
```

Now we need `account->role` to become the literal string `"admin"`.

Everything else — the login step with default creds, the embedded-NUL
password, the `sprintf`-into-`printf` format-string bug on the "completed
tasks" input — is identical in spirit to Rootstar Games. See that
writeup for the full breakdown of *why* each piece works; here we'll focus
on what's different.

## 2. Login step

```python
p.sendline(b"RockstarSeniorSWE\x00")
p.wait(1)
p.sendline("MyPasswordIsVeryV\016ryStrong#@.\x00")
# this can be found using gdb , do not blindly follow the main.c , compiler
# have his own touch
```

Same username, and the exact same "the real compiled byte is `\x0e`, not
`\x00`" gotcha as before — the compiler's actual layout of the password
constant doesn't perfectly match a naive reading of the `\x00` literal in
`main.c`, so the working byte was found empirically in GDB.

## 3. The format-string write — now targeting `"admin"`

```python
p.sendline("%" + str(int(u32("Dev\x00") - 33)) + "c" + "%6$n")
```

Two differences from Rootstar Games' payload jump out:

- **`u32("Dev\x00")`** instead of `u32("CEO\x00")` — wait, that looks odd
  at first glance, since the goal is to write `"admin"`, not overwrite
  with the old default `"Dev"`. This is the author reusing the printf
  character-count trick, but note the check here is
  `strcmp(account->role, isAdmin)` where `isAdmin = "admin"` is a **local
  stack variable** initialized fresh every time `challenge()` runs — its
  address, not its exact 4-byte value, is what actually matters for this
  particular positional argument. The `%6$n` write is landing on a
  *pointer* argument that — because the struct was reordered and `role`
  now sits at a **different offset relative to the stack frame** than in
  v1 — happens to correspond to a different stack slot (argument `6`
  instead of `15`), which the author again pinned down with GDB rather
  than by hand-calculating struct offsets.
- **`%6$n`** — a smaller positional index than Rootstar Games' `%15$n`,
  directly reflecting that reordering the struct fields shifted where
  useful pointers land among printf's phantom arguments.

The practical beginner takeaway: **moving one field in a struct is enough
to completely change every offset a format-string exploit depends on.**
The underlying bug (unsanitized `printf(result)`) is identical between v1
and v2, but the exact `%N$` argument index and byte value used to exploit
it had to be re-derived from scratch for the new layout — exactly what the
flavor text ("different struct, same bad habits") is hinting at.

## 4. Running it

```bash
python3 solver.py
```
Same flow as Rootstar Games: log in with default creds, send the crafted
`%c`/`%n` payload to flip `account->role` to `"admin"`, and
`showTopSecretAssest()` prints the flag.

## 5. Lesson

A format-string arbitrary-write exploit is **not portable across binary
layouts** — even a trivial struct field reorder (no logic change at all!)
forces you to redo the offset-hunting in GDB. This is also why real-world
format-string vulnerabilities are so fragile/version-specific: any compiler
flag, struct change, or library update can shift the exact argument index
you were relying on.
