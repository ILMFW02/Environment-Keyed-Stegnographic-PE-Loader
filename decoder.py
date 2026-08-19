from PIL import Image

def extract_data(steg_image_path, output_data_path):
    # 1. Mở ảnh đã giấu tin
    img = Image.open(steg_image_path)
    if img.mode != 'RGBA':
        print("[-] Lỗi: File ảnh không đúng định dạng RGBA tuần túy.")
        return

    pixels = img.getdata()
    
    # 2. Trích xuất 8 nibbles đầu tiên để đọc độ dài file (4 bytes = 8 nibbles)
    length_nibbles = []
    count = 0
    for pixel in pixels:
        for channel in pixel:
            length_nibbles.append(channel & 0x0F) # Lấy 4 bit thấp
            count += 1
            if count == 8: break
        if count == 8: break

    # Chuyển đổi 8 nibbles thành 4 bytes
    length_bytes = bytearray()
    for i in range(0, 8, 2):
        byte_val = (length_nibbles[i] << 4) | length_nibbles[i+1]
        length_bytes.append(byte_val)
        
    # Tính toán chính xác độ dài file dữ liệu được giấu
    data_len = int.from_bytes(length_bytes, byteorder='big')
    print(f"[+] Phát hiện payload ẩn có kích thước: {data_len} bytes")

    # 3. Tính toán tổng số nibbles cần trích xuất (bao gồm cả 4 byte header ban đầu)
    total_nibbles_to_read = (4 + data_len) * 2
    
    extracted_nibbles = []
    count = 0
    
    # Quét toàn bộ ảnh để lấy đủ số nibbles cần thiết
    for pixel in pixels:
        for channel in pixel:
            extracted_nibbles.append(channel & 0x0F)
            count += 1
            if count == total_nibbles_to_read: break
        if count == total_nibbles_to_read: break

    # Đóng gói các cặp khối 4-bit (nibbles) ngược trở lại thành các byte hoàn chỉnh
    full_bytes = bytearray()
    for i in range(0, len(extracted_nibbles), 2):
        byte_val = (extracted_nibbles[i] << 4) | extracted_nibbles[i+1]
        full_bytes.append(byte_val)

    # Loại bỏ 4 byte tiêu đề độ dài, chỉ lấy mảng dữ liệu gốc
    original_payload = full_bytes[4:]

    # 4. Ghi dữ liệu ra file nhị phân ban đầu
    with open(output_data_path, 'wb') as f:
        f.write(original_payload)
        
    print(f"[+] Khôi phục file thành công! Kết quả lưu tại: {output_data_path}")

# Chạy thử nghiệm script 2
if __name__ == "__main__":
    extract_data("steged2.png", "a_recovered.bin")