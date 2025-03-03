---
title: "PwnMe CTF 2025 Writeup"
date: 2025-03-02
draft: false
description: "Writeup for some challenges that I solved in PwnMe CTF 2025."
tags: ["ctf", "writeup", "blog"]
# series: ["Documentation"]
# series_order: 13
---

## Overview

Here are some of the challenges that I solved during PwnMe CTF 2025:

## Rev
### Back to the past

![back_to_the_past_0](writeups/pwnme_ctf_2025/back_to_the_past_0.png)

We are given a binary executable that encrypts the flag file. 

```bash
eenosse@ITDOLOZI:~/pwnmeCTF_2025/rev_Back_to_the_past$ ./backToThePast
Usage: ./backToThePast <filename>
eenosse@ITDOLOZI:~/pwnmeCTF_2025/rev_Back_to_the_past$ echo 1234 > test
eenosse@ITDOLOZI:~/pwnmeCTF_2025/rev_Back_to_the_past$ ./backToThePast test
time : 1740925301
```

Running the binary, we see that it prints out the current timestamp. So it might use the timestamp for encryption. Let's check that in IDA:

{{< details >}}
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
    char v3; // cl
    int v5; // edx
    char v6; // cl
    int v7; // edx
    char v8; // cl
    int v9; // eax
    char v10; // cl
    int v11; // [rsp+1Ch] [rbp-124h]
    unsigned int v12; // [rsp+20h] [rbp-120h]
    __int64 v13; // [rsp+28h] [rbp-118h]
    char v14[264]; // [rsp+30h] [rbp-110h] BYREF
    unsigned __int64 v15; // [rsp+138h] [rbp-8h]

    v15 = __readfsqword(0x28u);
    if ( argc > 1 )
    {
        v12 = time(0LL, argv, envp);
        printf((unsigned int)"time : %ld\n", v12, v5, v6);
        srand(v12);
        v13 = fopen64(argv[1], "rb+");
        if ( v13 )
        {
            while ( 1 )
            {
                v11 = getc(v13);
                if ( v11 == 0xFFFFFFFF )
                {
                    break;
                }

                fseek(v13, 0xFFFFFFFFFFFFFFFFLL, 1LL);
                v9 = rand();
                fputc(v11 ^ (unsigned int)(v9 % 0x7F), v13);
            }

            fclose(v13);
            strcpy(v14, argv[1]);
            strcat(v14, ".enc");
            if ( (unsigned int)rename(argv[1], v14) )
            {
                printf(
                    (unsigned int)"Can't rename %s filename to %s.enc",
                    (unsigned int)argv[1],
                    (unsigned int)argv[1],
                    v10);
                return 1;
            }
            else
            {
                return 0;
            }
        }
        else
        {
            printf((unsigned int)"Can't open file %s\n", (unsigned int)argv[1], v7, v8);
            return 1;
        }
    }
    else
    {
        printf((unsigned int)"Usage: %s <filename>\n", (unsigned int)*argv, (_DWORD)envp, v3);
        return 1;
    }
}
```
{{< /details >}}

Indeed, it uses the timestamp to set seed, then XOR our file with random numbers and write it to a `.enc` file. 

Things should be easy enough. However, when I tried to write a solve script using libc's `random`, it didn't give the right result. After debugging, I noticed that the random numbers of the program were different from mine. So something has been changed 🤔. 

It turns out the `srand` and `rand` functions are not the standard libc functions, but rather custom functions:

```c
__int64 __fastcall srand(int a1)
{
    __int64 result; // rax

    result = (unsigned int)(a1 - 1);
    seed = result;
    return result;
}
```

```c
unsigned __int64 rand()
{
    seed = 0x5851F42D4C957F2DLL * seed + 1;
    return (unsigned __int64)seed >> 0x21;
}
```

The `srand` function actually sets the seed to be equal to `a1 - 1`. I'm not sure if `rand` is different from the standard one, but we'll not care about that.

From this, I wrote a quick script to solve the challenge. Given that the challenge's description said `the binary would have been run in May 2024`, I bruteforced the timestamp from May to June:

```py
data = open("flag.enc", 'rb').read()

seed = 1740845724
def srand(s):
    global seed
    seed = s - 1
def rand():
    global seed
    seed = (0x5851F42D4C957F2D * seed + 1) & 0xffffffffffffffff
    return seed >> 0x21

for t in range(1714521600, 1717200000):
    srand(t)
    msg = []
    for c in data:
        rand_num = rand()
        msg.append(c ^ (rand_num % 0x7f))
    msg = bytes(msg)
    if b"PWNME" in msg:
        print(msg)
```

Running this will give us the flag: `PWNME{4baf3723f62a15f22e86d57130bc40c3}`

### C4 License

![c4_license_0](writeups/pwnme_ctf_2025/c4_license_0.png)



### Mimirev

Holder

### Super secure network

Holder

## Misc
### Decode Runner

Holder
