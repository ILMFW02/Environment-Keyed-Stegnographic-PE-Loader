import random

import random

def gf_mul(a, b):
    """Phép nhân trên GF(2^8) với đa thức 0x11b"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x11b
        b >>= 1
    return p & 0xFF

def gf_inv(n):
    """Tìm nghịch đảo của n trong GF(2^8) để thực hiện phép chia"""
    for i in range(1, 256):
        if gf_mul(n, i) == 1:
            return i
    return 0


def sss_encrypt_byte(secret_byte):
    # Bước 1: Đảm bảo đầu vào là byte
    S = secret_byte & 0xFF

    # Bước 2: Random hệ số a, b (phải khác 0 để không thành hàm hằng)
    a = random.randint(1, 255)
    b = random.randint(1, 255)

    # Bước 3: Chọn 5 giá trị x khác nhau (x từ 1-255)
    x_coords = random.sample(range(1, 256), 5)

    shares = []
    for x in x_coords:
        # Tính y = a*x^2 + b*x + S
        # x^2 = x * x
        x2 = gf_mul(x, x)
        # a*x^2
        term_a = gf_mul(a, x2)
        # b*x
        term_b = gf_mul(b, x)

        # y = term_a XOR term_b XOR S
        y = term_a ^ term_b ^ S
        shares.append((x, y))

    return shares


def sss_decrypt_byte(shares):
    secret = 0
    # Chỉ lấy đúng 3 mảnh đầu tiên để giải mã (theo ngưỡng k=3)
    shares = shares[:3]

    for i in range(len(shares)):
        xi, yi = shares[i]
        li = 1
        for j in range(len(shares)):
            if i != j:
                xj, _ = shares[j]
                # li = li * (xj / (xj XOR xi))
                denom = xj ^ xi
                inv_denom = gf_inv(denom)
                fraction = gf_mul(xj, inv_denom)
                li = gf_mul(li, fraction)

        # secret = secret XOR (yi * li)
        secret ^= gf_mul(yi, li)

    return secret


if __name__ == "__main__":
    # --- CHẠY THỬ ---
    input_key = 123
    print(f"Khóa gốc: {input_key}")

    # Tạo mảnh
    mảnh_khóa = sss_encrypt_byte(input_key)
    print("5 mảnh tạo ra:")
    for x, y in mảnh_khóa:
        print(f"  x={x}, y={y}") # Y phải khác nhau!

    # Giải mã với 3 mảnh ngẫu nhiên
    recovered = sss_decrypt_byte(random.sample(mảnh_khóa, 3))
    print(f"Khóa khôi phục: {recovered}")
