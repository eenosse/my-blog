---
title: "TPCTF 2025 Writeup - magicfile"
date: 2025-03-18
draft: false
description: "Writeup for some challenges that I solved in PwnMe CTF 2025."
tags: ["ctf", "writeup", "Reverse Engineering"]
# series: ["Documentation"]
# series_order: 13
---

## Overview

My quick writeup for `magicfile` challenge from TPCTF 2025.

## Magicfile

We're given a binary file which asks us for a flag. The flag must be 48 characters long.

If we type in a random strings like `'a'*48`, we will get the output: `ASCII text, with no line terminators`. So this seems to mimic the `file` command in Linux. We can look up the source code on Github and compare it with our file. 

The flag checking seems to be happening in `sub_59A0`, as it's the only place that uses our input:

```c
_BYTE *__fastcall sub_59A0(
        __int64 ms,
        __int64 input,
        unsigned __int64 input_len,
        __int64 input_,
        __int64 a5,
        __int64 a6)
{
    if ( !ms )
    {
        return 0LL;
    }

    if ( (unsigned int)sub_EBC0(ms, 1, input_len, input_, a5, a6) == 0xFFFFFFFF
      || (unsigned int)file_buffer(ms, 0xFFFFFFFFLL, 0LL, 0LL, input, input_len) == 0xFFFFFFFF )
    {
        return 0LL;
    }

    return file_getbuffer(ms);
}
```

This function will compare our input with some defined rules and return the result string. Checking the second function, we can see some strings like `[try zmagic %d]`, `[try tar %d]`, ... Looking this up, it's the function `file_buffer`. You can find this [here](https://github.com/file/file/blob/master/src/funcs.c#L323). 

Through debugging, I noticed that if we type in the flag format, it will stop for a while at `sub_153B0`, which is `file_softmagic`. This function will check our input using some "magic rules". The comparing function is `sub_13A70`. 

After more debugging, the flow seems to be like this:

1. It will iterate through each magic rules by `v25 = a2 + 0x178LL * v20;`.
2. It will first check that the first letters are `TPCTF`. If it's correct, it keeps checking, otherwise it will move to other rules (if any). 

```c
check_flag_magic = magiccheck(v23, a2 + 0x178LL * v20, v29, v30, v31, v32);
```
3. It will iterate through a sort of list of rules that check each letter. If the rule contains a result string, it will stop and return that string.

From the code, it seems like each rule is 0x178 bytes long. So I debugged to find the offset of the rules and dump it out:

```py
with open("magicfile_c970e3503feebf8274571f09d27cdd2f", 'rb') as f:
    sus = f.read()[0x212F4:]

for i in range(0, len(sus), 0xbc*2):
    print(sus[i:i+0xbc*2])
```

So what is the output when we input the right flag? By stringging the binary file, we can find that it's `Congratulations! You got the flag.` Looking for this in our dump, it's this rule:

```py
b'+\x00\x00\x00=\x00\x01\x00\x00\x00\x00\x00/\x00\x00\x00\x00\x00\x00\x00\xd4+\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Congratulations! You got the flag.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

Notice the `}` character there. Looking above this, we can see the flag:

![magicfile_1](writeups/TPCTF_2025/magicfile_1.png)

