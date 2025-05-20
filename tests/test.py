import os
import time


t = time.time()

with open("file.txt", 'r') as file:
    data = file.read(1)
print(len(data))

print(time.time() - t)
