# BabyEncryption
CHALLENGE DESCRIPTION
---------------------

> You are after an organised crime group which is responsible for the illegal weapon market in your country. As a secret agent, you have infiltrated the group enough to be included in meetings with clients. During the last negotiation, you found one of the confidential messages for the customer. It contains crucial information about the delivery. Do you think you can decrypt it?

Reversing
---------

First lets look at the files that are provided for this challange. There are two files in the password protected zip, the encryption algorithm and the encrypted message.

**Provided encryption algorithm:**

```text-plain
import string
from secret import MSG
def encryption(msg):
   ct = []
   for char in msg:
       ct.append((123 * char + 18) % 256)
   return bytes(ct)
ct = encryption(MSG)
f = open('./msg.enc','w')
f.write(ct.hex())
f.close() 
```

**And encrypted message:**

```text-plain
6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921
```

In the algorithm we can see that the secret string is imported, then the encryption function is defined.

First an empty list is initialized, then we loop through each character in the secret string.

```text-plain
for char in msg:
       ct.append((123 * char + 18) % 256)
   return bytes(ct) 
```

Multiplying the ascii value of the character by 123, then adding 18, then the remainder of this number divided by 256. Each remainder value is added to the list.

The function is called and assigned to the variable ct. The result is cast to hex and written to a file called msg.enc

Decryption
----------

In order to reverse the algorithm first we need to create a python script of our own. First convert the hex message in the file provided back to a string of bytes. To do this we'll use the bytes.fromhex() method and assign the result to a variable

```text-plain
encrypted = '6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921'

bytestr = bytes.fromhex(encrypted)
```

Next initialize an empty string which we will append each of the decoded values to.

```text-plain
secret = ''
```

Then create a nested loop, iterating through each of the valid ascii values (0 to 127) and if it matches the encrypted byte value add it to the decoded string and break the inner loop to move on to start guessing the next encrypted byte value in the bytestring.

```text-plain
for char in bytestr:
	for val in range(0, 127):
                if ((123 * val + 18) % 256) == char:
                	secret += chr(val)
                	break
```

Finally print the decrypted string to the console.

```text-plain
print(secret)
```

Solution
--------

Final decryption algorithm:

```text-plain
encrypted = '6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921'

bytestr = bytes.fromhex(encrypted)

secret = ''
for char in bytestr:
	for val in range(0, 127):
                if ((123 * val + 18) % 256) == char:
                	secret += chr(val)
                	break
print(secret)
```

Which returns the encrypted message containing the flag. Congrats you saved the world!

```text-plain
Th3 nucl34r w1ll 4rr1v3 0n fr1d4y.
HTB{********************************}
```