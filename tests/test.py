import os

filename = "file.banana.txt"
name, ext = os.path.splitext(filename)
print(name)  # outputs: file
print(ext)   # outputs: .txt