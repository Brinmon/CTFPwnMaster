import base64

# 创建包含 3 个字节的字节串
data = b'\x00' * 0x3
# Base64 编码
encoded_data = base64.b64encode(data)
# 输出 Base64 编码结果
print(f"Base64 编码结果: {encoded_data}")

binary_representation = ''.join(f'{byte:08b}' for byte in data)
print(f"原始数据的二进制表示:    {binary_representation}")
# 将编码结果转换为二进制

# 输出二进制格式
print(f"Base64 编码的二进制表示: {''.join(f'{byte:08b}' for byte in encoded_data)}")
binary_representation = ''.join(f'{byte:08b}' for byte in b'AAA')
print(f"Base64 编码的二进制表示: {binary_representation}")
