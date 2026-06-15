import hashlib
import sys

# Reconfigure stdout/stderr to UTF-8 to prevent charmap codec errors on Windows
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass


def calculate_md5(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    return md5_hash.hexdigest()

input_string = input("Nhập chuỗi cần băm: ")
md5_hash = calculate_md5(input_string)
print("Mã băm MD5 của chuỗi '{}' là: {}".format(input_string, md5_hash))
