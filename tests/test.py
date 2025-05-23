from pathlib import Path

path = Path("requirements.txt")
print([f for f in path.rglob("*")])