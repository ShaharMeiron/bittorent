from pathlib import Path

path = Path("requirements.txt")
print(path.read_bytes(3))