#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <string>
#include <vector>
#include <bcrypt.h>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

std::wstring get_path(DWORD pid) {
    std::wstring path = L"";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h != NULL) {
        wchar_t buf[MAX_PATH];
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
            path = buf;
        }
        CloseHandle(h);
    }
    return path;
}

std::wstring make_sha256(const std::wstring& path_to_file) {
    std::wstring hash_string = L"";
    HANDLE hFile = CreateFileW(path_to_file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return hash_string;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
        DWORD cbHashObject = 0;
        DWORD cbData = 0;
        
        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0) == 0) {
            std::vector<BYTE> hashObject(cbHashObject);
            
            if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, NULL, 0, 0) == 0) {
                BYTE buf[4096];
                DWORD reading = 0;
                bool ok = true;
                while (ReadFile(hFile, buf, sizeof(buf), &reading, NULL) && reading > 0) {
                    if (BCryptHashData(hHash, buf, reading, 0) != 0) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    BYTE h_res[32]; 
                    if (BCryptFinishHash(hHash, h_res, sizeof(h_res), 0) == 0) {
                        wchar_t key[65];
                        for (int i = 0; i < 32; ++i) {
                            swprintf_s(&key[i * 2], 3, L"%02x", h_res[i]);
                        }
                        hash_string = key;
                    }
                }
                BCryptDestroyHash(hHash);
            }
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    CloseHandle(hFile);
    return hash_string;
}

bool check_virus(const std::wstring& hash) {
    std::vector<std::wstring> virus_base;
    virus_base.push_back(L"eedfa3d702d73f4e1f74805e26b15e45a2789f663488f21bc9e4726ef6dfb776");
    virus_base.push_back(L"55d3122c153ff229b4e3415c8df1211bc048af3291244e8bc12a52cf12cf412f");

    for (size_t i = 0; i < virus_base.size(); ++i) {
        if (virus_base[i] == hash) {
            return true;
        }
    }
    return false;
}

bool heuristic_scan(const std::wstring& proc_name, const std::wstring& path) {
    std::wstring lower_name = proc_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);

    if (lower_name == L"svch0st.exe" || lower_name == L"notepadd.exe" || lower_name == L"explorer simulation.exe") {
        return true;
    }

    if (path.length() > 0) {
        std::wstring lower_path = path;
        std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::towlower);

        if (lower_path.find(L"\\appdata\\local\\temp\\") != std::wstring::npos) {
            if (lower_name.find(L"patch") != std::wstring::npos || 
                lower_name.find(L"crack") != std::wstring::npos || 
                lower_name.find(L"cheat") != std::wstring::npos) {
                return true;
            }
        }
    }
    return false;
}

void save_to_file() {
    std::wofstream file("processes.txt");
    if (!file.is_open()) return;

    HANDLE snp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snp == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 p32;
    p32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snp, &p32)) {
        do {
            std::wstring status = L"SAFE";
            std::wstring path = get_path(p32.th32ProcessID);
            
            if (check_virus(make_sha256(path)) == true || heuristic_scan(p32.szExeFile, path) == true) {
                status = L"VIRUS";
            }
            
            file << p32.th32ProcessID << L";" << p32.szExeFile << L";" << status << L"\n";
        } while (Process32Next(snp, &p32));
    }
    CloseHandle(snp);
    file.close();
}

bool kill_process(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h == NULL) return false;
    bool res = TerminateProcess(h, 0);
    CloseHandle(h);
    return res;
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        save_to_file();
        return 0;
    }

    std::string flag = argv[1];

    if (argc == 3 && flag == "--kill") {
        DWORD n_pid = std::stoul(argv[2]);
        if (kill_process(n_pid) == true) {
            return 100;
        }
        return 403;
    }

    if (argc == 3 && flag == "--check") {
        std::string s_path = argv[2];
        
        int len = MultiByteToWideChar(CP_UTF8, 0, s_path.c_str(), (int)s_path.length(), NULL, 0);
        std::wstring w_path(len, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s_path.c_str(), (int)s_path.length(), w_path.data(), len);
        
        std::wstring h = make_sha256(w_path);
        
        wchar_t name_buf[MAX_PATH];
        wchar_t ext_buf[MAX_PATH];
        _wsplitpath_s(w_path.c_str(), NULL, 0, NULL, 0, name_buf, MAX_PATH, ext_buf, MAX_PATH);
        
        std::wstring full_name = std::wstring(name_buf) + std::wstring(ext_buf);
        
        if (h.length() == 0 && full_name.empty()) return 404;
        if (check_virus(h) == true || heuristic_scan(full_name, w_path) == true) return 666;
        return 200;
    }

    return 0;
}
