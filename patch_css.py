import re

with open("frontend/index.css", "r") as f:
    css = f.read()

css = css.replace("padding: 4px 6px;", "padding: 8px 10px; width: 100%; height: 100%; box-sizing: border-box;")

with open("frontend/index.css", "w") as f:
    f.write(css)

print("CSS patched")
