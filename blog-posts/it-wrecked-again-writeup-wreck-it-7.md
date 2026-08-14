---
title: "Recovering Adversarial Evidence from Anonymous Memory - It Wrecked (Again) Write Up, Wreck IT 7.0 General Qualification"
pubDate: "2026-08-14"
description: 'Write-up for a forensic challenge titled "It Wrecked (Again)" which I authored for Wreck IT 7.0 General Qualification.'
---

Write-up for a challenge titled "It Wrecked (Again)" which I authored for Wreck IT 7.0 General Qualification. This challenge was the continuation of the Wreck IT 6.0 challenge titled "It Wrecked", which had a similar concept to this challenge (Linux forensics on a vulnerable binary).

### Background
The idea for this challenge came when I was playtesting its intended behavior. While I was carving for stealer traffic evidence from the memory using tools like bulk_extractor or MemProcFS, I couldn't find anything even though the stealer server received the stolen packets. This issue turned into a new idea for me with the logic of "if it got processed in memory, it should exist there." So I repeated the playtest and found out that my assumption was indeed correct, the ciphertext resides in the anonymous memory of the process.

### Initial Triage
This challenge is a Linux memory forensics challenge. Of course you need its ISF to parse it using Vol3. But I'm not going to walk through that "regular" part because it's just an ordinary procedure whenever you triage a memory artifact.

` vol -f memdump.lime --remote-isf-url 'https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json' linux.pslist`

I'll just run that command to see what processes are running in the current state of the captured memory. I use that --remote-isf-url so vol3 can directly check the repo and automatically use it as the ISF that fits the memory dump.

In the result of linux.pslist, there are two suspicious processes. One of them is intentionally a trap for sloppers who rely on automatic agentic AIs, and the other is a "decoy" that I put in the challenge.

```
0x8eeb17da0000  11618   11618   7402    session-handler 0       0       0       0       2026-05-12 15:02:14.826227 UTC Disabled
0x8eeb17da3d80  11619   11619   7402    gatekeeper      0       0       0       0       2026-05-12 15:02:14.826341 UTC Disabled
```

I'll skip that part and jump directly to the intended solution, which is the session-handler binary, and explain it.

If you decompile the binary, you will directly find some of the vulnerabilities in it.

```
      while ( *__errno_location() == 4 );
      perror("accept");
      close(fd);
      munmap(g_rwx_page, 0x1000u);
      return 0;
    }
    else
    {
      perror("listener");
      munmap(g_rwx_page, 0x1000u);
      return 1;
    }
  }
}
```

```
__int64 __fastcall serve_client(unsigned int a1)
{
  __int64 result; // rax
  _BYTE v2[512]; // [rsp+10h] [rbp-200h] BYREF

  send_text(a1, "WRECK IT 7.0 session handler\ncheck in before requesting status data\n");
  while ( 2 )
  {
    list_menu(a1);
    result = recv_line(a1, v2, 512);
    if ( result > 0 )
    {
      switch ( v2[0] )
      {
        case '1':
          create_session(a1);
          continue;
        case '2':
          show_active_session(a1);
          continue;
        case '3':
          run_status_callback(a1);
          continue;
        case '4':
          append_note(a1);
          continue;
        case '5':
          release_active_session(a1);
          continue;
        case '6':
          prime_lease(a1, 0);
          continue;
        case '7':
          prime_lease(a1, 1);
          continue;
        case '8':
          write_to_rwx_page(a1);
          continue;
        case '9':
          result = send_text(a1, "bye\n");
          break;
        default:
          send_text(a1, "unknown choice\n");
          continue;
      }
    }
    break;
  }
  return result;
}
```

```
__int64 __fastcall prime_lease(unsigned int a1, char a2)
{
  int v3; // r8d
  int v4; // r9d
  _BYTE v5[524]; // [rsp+10h] [rbp-220h] BYREF
  int v6; // [rsp+21Ch] [rbp-14h]
  void *s; // [rsp+220h] [rbp-10h]
  int free_slot; // [rsp+22Ch] [rbp-4h]

  free_slot = find_free_slot(g_leases, 8);
  if ( free_slot < 0 )
    return send_text(a1, "all lease slots are busy\n");
  s = malloc(0x50u);
  if ( !s )
    return send_text(a1, "lease allocation failed\n");
  memset(s, 0, 0x50u);
  snprintf((char *)s, 0x20u, "maint-lease-%d", free_slot);
  snprintf((char *)s + 32, 0x10u, "ops-%d", free_slot);
  *((_QWORD *)s + 6) = g_rwx_page;
  *((_QWORD *)s + 7) = 4096;
  *((_QWORD *)s + 8) = free_slot | (unsigned __int64)(time(0) << 8);
  *((_QWORD *)s + 9) = emit_safe_notice;
  if ( a2 )
  {
    send_text(a1, "lease template (hex blob, overlays the freed session chunk):\n> ");
    if ( recv_line(a1, v5, 512) <= 0 )
    {
      free(s);
      return send_text(a1, "template import aborted\n");
    }
    v6 = decode_hex_blob(v5, s, 80);
    if ( v6 < 0 )
    {
      free(s);
      return send_text(a1, "invalid template bytes\n");
    }
    if ( !*((_QWORD *)s + 6) )
      *((_QWORD *)s + 6) = g_rwx_page;
    if ( !*((_QWORD *)s + 7) )
      *((_QWORD *)s + 7) = 4096;
  }
  g_leases[free_slot] = s;
  return sendf(a1, (unsigned int)"lease %d primed\n", free_slot, (unsigned int)"lease %d primed\n", v3, v4);
}
```


```
void __fastcall create_session(unsigned int a1)
{
  int v1; // r8d
  int v2; // r9d
  _BYTE v3[512]; // [rsp+10h] [rbp-210h] BYREF
  void *ptr; // [rsp+210h] [rbp-10h]
  int free_slot; // [rsp+21Ch] [rbp-4h]

  free_slot = find_free_slot(g_sessions, 8);
  if ( free_slot >= 0 )
  {
    ptr = calloc(1u, 0x50u);
    if ( ptr )
    {
      *((_QWORD *)ptr + 6) = calloc(1u, 0x60u);
      if ( *((_QWORD *)ptr + 6) )
      {
        *((_QWORD *)ptr + 7) = 96;
        *((_QWORD *)ptr + 8) = ((__int64)free_slot << 32) ^ time(0);
        *((_QWORD *)ptr + 9) = emit_host_status;
        send_text(a1, "username:\n> ");
        if ( recv_line(a1, v3, 512) < 0
          || (copy_cstr(ptr, 32, v3), send_text(a1, "employee id:\n> "), recv_line(a1, v3, 512) < 0) )
        {
          free(*((void **)ptr + 6));
          free(ptr);
        }
        else // UAF vuln
        {
          copy_cstr((char *)ptr + 32, 16, v3);
          g_sessions[free_slot] = ptr;
          g_active_session = ptr;
          g_active_index = free_slot;
          g_active_is_stale = 0;
          sendf(
            a1,
            (unsigned int)"checked in at slot %d\nmaintenance profile ready\n",
            free_slot,
            (unsigned int)"checked in at slot %d\nmaintenance profile ready\n",
            v1,
            v2);
        }
      }
      else
      {
        free(ptr);
        send_text(a1, "note allocation failed\n");
      }
    }
    else
    {
      send_text(a1, "allocation failed\n");
    }
  }
  else
  {
    send_text(a1, "all session slots are busy\n");
  }
}
```

### Vulnerability

The comment `// UAF vuln` I left in that decompiled output points at the exact bug. `create_session` allocates a `Session` struct (`calloc(1, 0x50)`, 80 bytes) plus a separate 0x60-byte chunk for the note, then stores the pointer in two places: `g_sessions[free_slot]` (the "official" slot array) and `g_active_session` (a single global "currently checked in" pointer, basically a shortcut so the menu doesn't have to ask which slot you mean every time).

The bug lives in `release_active_session` (menu option 5):

```c
free(g_active_session->note);
free(g_active_session);
g_sessions[g_active_index] = NULL;
g_active_is_stale = true;
```

It frees the session and clears the slot array entry, but `g_active_session` itself never gets set back to NULL. It just flips a flag (`g_active_is_stale`) that, spoiler, nothing outside of `show_active_session` actually checks. So after you release, `g_active_session` is a dangling pointer into freed heap memory. Textbook use-after-free.

Just freeing the session chunk doesn't do much on its own. You need something to land in that exact freed memory with attacker-controlled bytes, and that's what `prime_lease` (menu option 6/7) is for.

`OpsLease` and `Session` are the same size on purpose (both 0x50, 80 bytes), field for field:

```
offset  Session          OpsLease
0x00    username[32]     label[32]
0x20    employee_id[16]  operator_id[16]
0x30    note (ptr)       scratch_page (ptr)
0x38    note_cap         page_len
0x40    ticket_id        lease_id
0x48    status_cb (fn)   completion_hook (fn)
```

So if glibc hands the just-freed `Session` chunk back out for the next `OpsLease` allocation, whatever bytes you put into the `OpsLease` land at the same addresses the old `Session` used to occupy, including that last field, the function pointer.

Menu option 7 is the one that actually gives you control over the bytes. It lets you send a raw hex blob that gets `decode_hex_blob`'d straight onto the freshly allocated `OpsLease`, byte for byte, with no validation on the function pointer field at all. So an attacker can craft a fake `OpsLease` where `completion_hook` (offset 0x48) is any address they want.

Offset 0x48 in the old `Session` layout is `status_cb`, the function pointer `run_status_callback` (menu option 3) blindly calls:

```c
g_active_session->status_cb(client_fd, g_active_session);
```

`g_active_session` is still that stale pointer from before. After the overlap, the memory it points to isn't a `Session` anymore — it's the attacker's `OpsLease`, so `status_cb` at 0x48 is really whatever the attacker wrote as `completion_hook`. Call menu 3 and instead of getting CPU/RAM status back, you get a jump straight into attacker-controlled code. A function-pointer overwrite via UAF, just wearing a "maintenance lease" costume.

### Exploit Flow

The address you want to jump into is the RWX scratch page (`g_rwx_page`), a 4KB `mmap(PROT_READ|WRITE|EXEC, MAP_PRIVATE|MAP_ANONYMOUS)` region the service sets up at startup for "staging maintenance blobs" (menu option 8). The binary itself is compiled `-no-pie`, so its own code and data sit at fixed addresses, but this page comes from an anonymous mmap, which still gets ASLR'd per run. That's why you can't hardcode it — you have to leak it first.

Conveniently, menu option 8 (`write_to_rwx_page`) leaks it for free in its own response:

```
staged %d bytes into scratch page %p
```

So the exploit flow is: stage a throwaway byte to leak the page address, compile the real shellcode with that address baked in as the KDF seed (more on that below), restage the real shellcode into the same page, check in, release, overlap with a crafted lease pointing `completion_hook` at `rwx_page + entry_offset`, then hit menu 3 to trigger it. `entry_offset` matters too: since the shellcode is built freestanding with `-nostdlib`, the helper functions (`kdf_derive`, `custom_encrypt`, `mem_wipe`) can end up placed before `_start` in the raw `.text` blob, so `_start` isn't necessarily byte 0 of the staged page. You have to resolve it (`nm` + `readelf`) and add it as an offset on top of the leaked base.

### Finding the payload

`linux.malfind` is the plugin that gets you moving here. It flags anonymous memory regions that look like injected code, and the RWX scratch page is exactly that: anonymous, no backing file, and executable, which is a big red flag compared to normal RW or RX file-backed mappings. That gives you the base address of the scratch page, which is also the seed the shellcode used for its whole key chain.

The second mapping (the RW-only one holding the ciphertext) won't get flagged by `malfind` the same way since it's not executable, so you're better off dumping the full set of anonymous mappings for the compromised PID and picking out the blob that isn't zero and isn't obviously plaintext. It tends to sit close to the flagged RWX page in the address space since both were created back to back by the same process, which helps narrow it down once you know what you're looking for.

### Carving the Memory
When this challenge was released for the Qualification, there was a tool called "MemNixFS," which is the Linux-targeted version of MemProcFS. This tool allowed people to parse a memory dump and treat it like a disk dump. We can leverage this tool specifically to carve the ciphertext from the vulnerable binary's process memory.

When I did the playtest, MemNixFS was not yet released, so my own intended way was to carve it directly from the LiME file by inspecting the strings related to the binary. But if you think about it, it might sound like guesswork, yet there are a lot of other options I haven't explored yet.

```
C:\1Jonathan\apps\MemNixFS-1.2-win64>memnixfs --dump "C:\1Jonathan\CTFS\research-dir\vibe-authoring\wreck-it\dist\memdump.lime" --auto-fetch mount M:
Opening dump: C:\1Jonathan\CTFS\research-dir\vibe-authoring\wreck-it\dist\memdump.lime
Format: LiME
Detected kernel release: 5.15.0-25-generic (distro=ubuntu, banner shown above)
Loading symbols: C:\Users\Zenbook\AppData\Local\MemNixFS\symbols\5.15.0-25-generic.json.xz (auto-discover-cache)
/fs: 2873 dirs, 22958 regular files, 3277 symlinks (552 inodes skipped — no resolvable path, 1301 pseudo-fs skipped)
Loaded in 49.4s
Mounted at M:; press Ctrl+C to unmount.
```

Upon mounting the memory as an `M:` drive, you can directly check the process folder of the vulnerable binary, which resides at `M:\proc\11618-session-handler`, and you will see a dump file named `proc.dmp`. If you inspect the raw data of this dump, it has an "ELF" header, which means this is probably a coredump of the process.

If we check the maps file in the process directory of MemNixFS.

```
000000400000-000000401000 r--p 00000000 00:00 0          [mapped]
000000401000-000000403000 r-xp 00001000 00:00 0          [mapped]
000000403000-000000404000 r--p 00003000 00:00 0          [mapped]
000000404000-000000405000 r--p 00003000 00:00 0          [mapped]
000000405000-000000406000 rw-p 00004000 00:00 0          [mapped]
00000097b000-00000099c000 rw-p 00000000 00:00 0          
7f4543ac1000-7f4543ac4000 rw-p 00000000 00:00 0          
7f4543ac4000-7f4543aec000 r--p 00000000 00:00 0          [mapped]
7f4543aec000-7f4543c81000 r-xp 00028000 00:00 0          [mapped]
7f4543c81000-7f4543cd9000 r--p 001bd000 00:00 0          [mapped]
7f4543cd9000-7f4543cda000 ---p 00215000 00:00 0          [mapped]
7f4543cda000-7f4543cde000 r--p 00215000 00:00 0          [mapped]
7f4543cde000-7f4543ce0000 rw-p 00219000 00:00 0          [mapped]
7f4543ce0000-7f4543ced000 rw-p 00000000 00:00 0          
7f4543cfb000-7f4543cfe000 rw-p 00000000 00:00 0          
7f4543cfe000-7f4543d00000 r--p 00000000 00:00 0          [mapped]
7f4543d00000-7f4543d2a000 r-xp 00002000 00:00 0          [mapped]
7f4543d2a000-7f4543d35000 r--p 0002c000 00:00 0          [mapped]
7f4543d35000-7f4543d36000 rwxp 00000000 00:00 0          
7f4543d36000-7f4543d38000 r--p 00037000 00:00 0          [mapped]
7f4543d38000-7f4543d3a000 rw-p 00039000 00:00 0          [mapped]
7ffc0d431000-7ffc0d452000 rwxp 00000000 00:00 0          
7ffc0d578000-7ffc0d57c000 r--p 00000000 00:00 0          
7ffc0d57c000-7ffc0d57e000 r-xp 00000000 00:00 0          
```

Entries labeled with `[mapped] `and non-zero progressing file offsets (e.g., 00001000, 00028000, 00215000) represent file-backed mappings (such as the main binary image, libc.so, and ld.so) whose absolute file paths could not be resolved by the forensic tool. Anonymous memory regions are identified by a zeroed offset (00000000) and an empty trailing path field.


We also can see
`7f4543d35000-7f4543d36000 rwxp 00000000 00:00 0`
the rwx region which probably where the shellcode is residing.

Loading proc.dmp into GDB with pwndbg and disassembling the entry point of this RWX region reveals the shellcode behavior. It derives multiple 64-bit encryption keys directly from the base address of the RWX page (`0x7f4543d35000`) using bitwise rotations and multiplications.

It opens /secret.txt via SYS_open, dynamically allocates a buffer via sys_mmap, reads the file content into this buffer, and subsequently deletes the file from disk using SYS_unlink.

And then applies an 8-byte block shift, multi-round XOR operations against derived keys, and an index permutation loop in-place on the allocated buffer.

The shellcode exfiltrates the ciphertext over a TCP socket (192.168.154.1:4444), zeroes out the stack frame to destroy encryption keys, and enters an infinite SYS_pause loop.

Due to Linux x86_64's top-down memory allocation strategy, the SYS_mmap call placed the heap/scratch buffer into the first available contiguous gap right below ld-linux, mapping it at `0x7f4543cfb000`.

This anonymous mapping yields the 34-byte ciphertext:
```
pwndbg> x/34bx 0x7f4543cfb000
0x7f4543cfb000: 0xbe    0x1f    0xef    0x19    0x80    0x54    0xe1    0x44
0x7f4543cfb008: 0x0f    0x90    0xc9    0x80    0xe8    0x0d    0x9f    0x93
0x7f4543cfb010: 0xd7    0xcc    0x9a    0xe8    0x0f    0xba    0xe3    0x58
0x7f4543cfb018: 0x54    0x37    0xf7    0x0a    0xb1    0x53    0xbc    0x67
0x7f4543cfb020: 0xe5    0x30
```

### Solving the Challenge

Once you have the RWX base address and the ciphertext blob pulled out of the dump, recovering the flag is just replaying the same KDF chain on the solver side and running the cipher steps backwards.

You need to derive the `stub_key`, `enc_key1`, and `enc_key2` exactly the way the shellcode did, then undo the custom encryption in reverse order by replaying the looping swap from the last index back to the first, xor `enc_key2`, xor `enc_key1`, then undo the 8-byte left rotate by shifting the last 8 bytes back to the front. After all of that you will get the real flag.
