#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <string>
#include <vector>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

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

std::wstring make_md5(const std::wstring& path_to_file) {
    std::wstring hash_string = L"";
    HANDLE hFile = CreateFileW(path_to_file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return hash_string;

    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(prov, CALG_MD5, 0, 0, &hash)) {
            BYTE buf[1024];
            DWORD reading = 0;
            bool ok = true;
            while (ReadFile(hFile, buf, sizeof(buf), &reading, NULL) && reading > 0) {
                if (!CryptHashData(hash, buf, reading, 0)) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                BYTE h_res[16];
                DWORD h_len = 16;
                if (CryptGetHashParam(hash, HP_HASHVAL, h_res, &h_len, 0)) {
                    wchar_t key[33];
                    for (int i = 0; i < 16; ++i) {
                        swprintf_s(&key[i * 2], 3, L"%02x", h_res[i]);
                    }
                    hash_string = key;
                }
            }
            CryptDestroyHash(hash);
        }
        CryptReleaseContext(prov, 0);
    }
    CloseHandle(hFile);
    return hash_string;
}

bool check_virus(const std::wstring& hash) {
    std::vector<std::wstring> virus_base;
    virus_base.push_back(L"44d88612fea8a8f36de82e1278abb02f");
    virus_base.push_back(L"3a52ce780950d4d969792a2559cd935a");

    for (size_t i = 0; i < virus_base.size(); ++i) {
        if (virus_base[i] == hash) {
            return true;
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
            if (path.length() > 0) {
                std::wstring h = make_md5(path);
                if (check_virus(h) == true) {
                    status = L"VIRUS";
                }
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
        std::wstring w_path = L"";
        for (size_t i = 0; i < s_path.length(); ++i) {
            w_path += (wchar_t)s_path[i];
        }

        std::wstring h = make_md5(w_path);
        if (h.length() == 0) return 404;
        if (check_virus(h) == true) return 666;
        return 200;
    }

    return 0;
}
