#! /usr/bin/env python

from numpy import random

f = open("aes.key", "wb")
key = random.randint(0, 256, 16, int)
f.write(bytes(list(key)))
f.close()

for k in key:
    print(f"{k:02x}", end=' ')
print()
