import os
from PIL import Image
import argparse

def embed_data(image_path, data_path, output_path):
    if not os.path.exists(data_path):
        print(f"[-] Không tìm thấy file dữ liệu: {data_path}")
        return
        
    # 1. Đọc dữ liệu nhị phân từ file cần giấu
    with open(data_path, 'rb') as f:
        data_bytes = f.read()
    
    data_len = len(data_bytes)
    print(f"[+] Kích thước file dữ liệu: {data_len} bytes (~{data_len/(1024*1024):.2f} MB)")

    # Thêm 4 byte đầu tiên lưu độ dài của dữ liệu (Big-endian) để phục vụ việc giải mã
    full_data = data_len.to_bytes(4, byteorder='big') + data_bytes

    # Tách dữ liệu thành các khối 4-bit (nibbles)
    # Mỗi byte sẽ tách thành 2 nibbles: 4 bit cao và 4 bit thấp
    nibbles = []
    for byte in full_data:
        nibbles.append((byte >> 4) & 0x0F)  # 4 bit cao
        nibbles.append(byte & 0x0F)         # 4 bit thấp
    
    total_nibbles = len(nibbles)

    # 2. Mở ảnh gốc và KIỂM TRA ĐỊNH DẠNG RGBA
    img = Image.open(image_path)
    print(f"[+] Định dạng ảnh gốc (Mode): {img.mode}")
    
    if img.mode != 'RGBA':
        print("[-] CẢNH BÁO: Ảnh không phải định dạng RGBA.")
        print("[*] Đang tiến hành chuyển đổi ảnh sang hệ RGBA...")
        img = img.convert('RGBA')
        print(f"[+] Chuyển đổi thành công. Mode hiện tại: {img.mode}")

    width, height = img.size
    total_pixels = width * height
    # Mỗi pixel RGBA có 4 kênh, mỗi kênh chứa 1 nibble (4 bits). 
    # Vậy 1 pixel chứa được 4 nibbles.
    max_nibbles_capacity = total_pixels * 4

    print(f"[+] Độ phân giải ảnh: {width}x{height} ({total_pixels} pixels)")
    print(f"[+] Sức chứa tối đa của ảnh với LSB 4 tầng: {max_nibbles_capacity // 2} bytes")

    if total_nibbles > max_nibbles_capacity:
        print("[-] LỖI: Ảnh quá nhỏ, không đủ sức chứa lượng dữ liệu này!")
        return

    # 3. Tiến hành giấu tin
    pixels = list(img.getdata())
    new_pixels = []
    nibble_idx = 0

    for pixel in pixels:
        if nibble_idx < total_nibbles:
            r, g, b, a = pixel
            
            # Thay thế 4 bit thấp của từng kênh màu bằng toán tử bitwise
            if nibble_idx < total_nibbles:
                r = (r & 0xF0) | nibbles[nibble_idx]
                nibble_idx += 1
            if nibble_idx < total_nibbles:
                g = (g & 0xF0) | nibbles[nibble_idx]
                nibble_idx += 1
            if nibble_idx < total_nibbles:
                b = (b & 0xF0) | nibbles[nibble_idx]
                nibble_idx += 1
            if nibble_idx < total_nibbles:
                a = (a & 0xF0) | nibbles[nibble_idx]
                nibble_idx += 1
                
            new_pixels.append((r, g, b, a))
        else:
            # Nếu đã giấu hết tin, giữ nguyên các pixel còn lại
            new_pixels.append(pixel)

    # Tạo ảnh mới và lưu lại
    steg_img = Image.new('RGBA', img.size)
    steg_img.putdata(new_pixels)
    steg_img.save(output_path, 'PNG')
    print(f"[+] Đã giấu tin thành công! File đầu ra: {output_path}")

# Chạy thử nghiệm script 1
# if __name__ == "__main__":
#     embed_data("photo.png", "m.bin", "mphoto.png")


if __name__ == "__main__":
    # Khởi tạo bộ phân tích tham số
    parser = argparse.ArgumentParser(description="Giấu file m.bin vào một ảnh bất kỳ.")
    
    # Định nghĩa tham số ảnh đầu vào
    parser.add_argument("--image", default="photo.png", help="Đường dẫn ảnh gốc RGBA (Mặc định: photo.png)")
    
    args = parser.parse_args()

    # Truyền tham số ảnh động từ user, giữ nguyên dữ liệu vào m.bin và đầu ra mphoto.png
    embed_data(args.image, "m.bin", "mphoto.png")