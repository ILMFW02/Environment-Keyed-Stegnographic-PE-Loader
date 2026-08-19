import os
import sys
import subprocess
import argparse

def run_script(cmd_args):
    """Hàm bổ trợ để chạy lệnh hệ thống và bắt lỗi nếu có."""
    script_name = cmd_args[1]  # Tên file script .py
    
    print("\n" + "="*60)
    print(f"[*] ĐANG THỰC THI: {' '.join(cmd_args)}")
    print("="*60)
    
    if not os.path.exists(script_name):
        print(f"[-] LỖI: Không tìm thấy file script '{script_name}' trong thư mục hiện tại!")
        return False
    
    try:
        # Thực thi lệnh và kiểm tra trạng thái trả về
        result = subprocess.run(cmd_args, check=True)
        if result.returncode == 0:
            print(f"[+] Hoàn thành: Script '{script_name}' chạy thành công.")
            return True
    except subprocess.CalledProcessError as e:
        print(f"[-] LỖI: '{script_name}' dừng đột ngột (Mã lỗi: {e.returncode}).")
        return False
    except Exception as e:
        print(f"[-] LỖI HỆ THỐNG khi kích hoạt '{script_name}': {e}")
        return False

def main():
    # 1. Khởi tạo bộ nhận diện tham số cho script tổng
    parser = argparse.ArgumentParser(description="Script tự động hóa quy trình đóng gói và giấu tin.")
    
    parser.add_argument("--json", default="target_N.json", help="Đường dẫn file cấu hình JSON (Mặc định: target_N.json)")
    parser.add_argument("--payload", default="msource.exe", help="Đường dẫn file payload (Mặc định: msource.exe)")
    parser.add_argument("--image", default="photo.png", help="Đường dẫn ảnh vỏ bọc RGBA (Mặc định: photo.png)")
    
    args = parser.parse_args()
    
    print("[*] KHỞI ĐỘNG PIPELINE TỰ ĐỘNG HÓA...")
    
    # 2. BƯỚC 1: Gọi builder_new1.py và truyền tham số --json, --payload
    builder_cmd = [sys.executable, "builder_new1.py", "--json", args.json, "--payload", args.payload]
    if not run_script(builder_cmd):
        print("\n[-] DỪNG TIẾN TRÌNH: Bước dựng mã nguồn (builder) thất bại.")
        sys.exit(1)
        
    # 3. BƯỚC 2: Gọi image_encoder.py và truyền tham số --image
    encoder_cmd = [sys.executable, "image_encoder.py", "--image", args.image]
    if not run_script(encoder_cmd):
        print("\n[-] DỪNG TIẾN TRÌNH: Bước giấu tin vào ảnh (image_encoder) thất bại.")
        sys.exit(1)
        
    print("\n" + "="*60)
    print("[+] THÀNH CÔNG: Đã hoàn thành toàn bộ quy trình tự động hóa!")
    print("="*60)

if __name__ == "__main__":
    main()