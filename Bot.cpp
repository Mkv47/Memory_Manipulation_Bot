#include "header.h"

DWORD processID;
HWND hwnd;
HANDLE process_handle;
uintptr_t _address;
uintptr_t loc_address;
uintptr_t c_Status_address;
uintptr_t write_address;
uintptr_t read_address;
DWORD old_found_address;
std::vector<uintptr_t> old_addresses;
int check = 0;

std::vector<BYTE> hexStringToByteVector(const std::string& hex) {
    std::vector<BYTE> bytes;
    std::istringstream hex_stream(hex);
    std::string byte;
    //std::cout << "Here 1" << std::endl;
    while (hex_stream >> byte) {
        if (byte == "?") {
            bytes.push_back(0xFF);
        }else {
            bytes.push_back(static_cast<BYTE>(std::stoi(byte, nullptr, 16)));
        }
    }
    return bytes;
}

void delay(int seconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(seconds));
}

void sendKeyToWindow(HWND hwnd, UINT key)
{
    //key press
    PostMessage(hwnd, WM_KEYDOWN, key, 0);

    //key release
    PostMessage(hwnd, WM_KEYUP, key, 0);
}

void GetProcessIDFromWindow(LPCSTR windowName) {
    while (hwnd == NULL)
    {
        hwnd = FindWindowA(NULL, (windowName));
        GetWindowThreadProcessId(hwnd, &processID);
        if(hwnd == NULL){std::cout << "No program found please make sure that the program has started..." << std::endl;
            std::chrono::seconds delay(2000);
            std::this_thread::sleep_for(delay);
        }
    }
}
bool find_pattern_in_memory(const std::vector<BYTE>& buffer, const std::vector<BYTE>& pattern, size_t& found_offset, uintptr_t address) {
    size_t buffer_size = buffer.size();
    size_t pattern_size = pattern.size();
    for (size_t i = 0; i <= buffer_size - pattern_size; i += 4) {
        bool match = true;
        auto it = std::find(old_addresses.begin(), old_addresses.end(), address + i);
        if (it == old_addresses.end())
        {
            for (size_t j = 0; j < pattern_size; ++j) { 
                if (pattern[j] != 0xFF && buffer[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                found_offset = i;
                return true;
            }
        }
    }
    return false;
}

void read_all_memory_once(DWORD processId, const std::vector<BYTE>& byte_pattern,std::ofstream& fileName, uintptr_t s_point) {
    process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    
    if (process_handle == NULL) {
        std::cerr << "Failed to open process handle. Error code: " << GetLastError() << std::endl;
        return;
    }
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = s_point;
    while (VirtualQueryEx(process_handle, (LPCVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READONLY || mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READ)) {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            
            if (ReadProcessMemory(process_handle, (LPCVOID)address, buffer.data(), mbi.RegionSize, &bytesRead)) {
                //std::cout << "Read " << bytesRead << " bytes from address: " << std::hex << address << std::endl;

                size_t found_offset = 0;

                if (find_pattern_in_memory(buffer, byte_pattern, found_offset, address)) {
                    // Calculate the actual address where the pattern was found

                    DWORD found_address = address + found_offset;
                    _address = found_address;
                    std::cout << std::hex << "address " << found_address << std::endl;
                    break;
                }
            } else {
                std::cerr << "Failed to read memory at address: " << std::hex << address << " Error code: " << GetLastError() << std::endl;
            }
        }
        address += mbi.RegionSize;
    }

    CloseHandle(process_handle);
}


void read_all_memory_loop(DWORD processId, const std::vector<BYTE>& byte_pattern,std::ofstream& fileName, uintptr_t s_point, uintptr_t p_check, uintptr_t p_to_check) {
    process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (process_handle == NULL) {
        std::cerr << "Failed to open process handle. Error code: " << GetLastError() << std::endl;
        return;
    }
    if (p_check != 0)
    {
        ReadProcessMemory(process_handle, (LPCVOID)p_check, &check, sizeof(check), NULL);
        //std::cout << check << std::endl;
    }
    
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = s_point;

    while (VirtualQueryEx(process_handle, (LPCVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READONLY || mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READ)) {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(process_handle, (LPCVOID)address, buffer.data(), mbi.RegionSize, &bytesRead)) {
                //std::cout << "Read " << bytesRead << " bytes from address: " << std::hex << address << std::endl;

                size_t found_offset = 0;

                if (find_pattern_in_memory(buffer, byte_pattern, found_offset, address)) {
                    // Calculate the actual address where the pattern was found
                    uintptr_t found_address = address + found_offset;
                    //std::cout << std::hex << found_address  << " | " << p_to_check << std::endl;
                    auto it = std::find(old_addresses.begin(), old_addresses.end(), found_address);
                    if (check != 0 && it == old_addresses.end()) {
                        //std::cout << "The check value is not 0 therefor check sucsess !!" << std::endl;
                        read_address = found_address;
                        break;
                    }else if (found_address != p_to_check && it == old_addresses.end()) {
                        //std::cout << "The check value is "<< check <<" therefor check if address is equle to and old address" << std::endl;
                        read_address = found_address;
                        ReadProcessMemory(process_handle, (LPCVOID)((address + found_offset) - 0x108 ), &check, sizeof(check), NULL);
                        if (check != 0)
                        {
                            //std::cout << "The check value is "<< check <<" and not 0 and it doesn't match any old address" << std::endl;
                            break;
                        }else {
                        //std::cout << "The check value is 0 and it doesn't match any old address there for it will be tested will bet tested again" << std::endl;
                        old_addresses.push_back(p_to_check);
                        p_to_check = read_address;
                        address -= mbi.RegionSize;
                        }
                    }else {
                        //std::cout << "The check value is 0 and it matched an old address again" << std::endl;
                        old_addresses.push_back(p_to_check);
                        p_to_check = read_address;
                        //std::cout << "here 3" << std::endl;
                    }
                }
            } else {
                //std::cerr << "Failed to read memory at address: " << std::hex << address << " Error code: " << GetLastError() << std::endl;
            }
        }
        address += mbi.RegionSize;
        if (address > 0x1A000000)
        {
            break;
        }
        
    }
    CloseHandle(process_handle);
}

int main() {
    GetProcessIDFromWindow("Warspear Online");


    SIZE_T bytesWritten;


    uintptr_t address1;
    uintptr_t address2;
    uintptr_t address3;
    uintptr_t address4;
    uintptr_t address5;
    uintptr_t address6;
    uintptr_t address7;
    uintptr_t address8;
    uintptr_t address9;



    LPVOID addressToWrite1;
    LPVOID addressToWrite2;
    LPVOID addressToRead;
    LPVOID check_address;
    LPVOID is_combat;


    int valueToRead;
    int valueToWrite;
    int cHp;
    int cValueToWrite1;
    int cValueToWrite2;
    int valueToCheck;
    int isCombatValue;
    int pCursorLoc;
    int cursorStatus;
    char direction;
    int dValue;
    unsigned int cStatusValue;
    int locValue;
    int locValueFX;
    int locValueFY;


    std::fstream pattrenFile;
    std::fstream patestFile;
    std::string pattern;
    std::ofstream outputFile("./Data/FoundAddresses.txt", std::ios::app);


    patestFile.open("./Data/Patest.txt", std::ios::in);
    pattrenFile.open("./Data/Pattrens.txt", std::ios::in);


    // Open the target process with required access rights
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Could not open process. Error: " << GetLastError() << std::endl;
        return 1;
    }


    hwnd = FindWindowW(NULL, L"Warspear Online");
    for (size_t i = 0; i < 3; i++)
    {
        if (std::getline(pattrenFile, pattern))
        {
            std::cout << "\nLine read from file: " << pattern << " | " << i << std::endl;
            std::vector<BYTE> byte_pattern = hexStringToByteVector(pattern);
            read_all_memory_once(processID, byte_pattern, outputFile, 0x0B000000);
            
            if (i == 0)
            {
                write_address = _address;
            }else if (i == 1)
            {
                loc_address = _address;
            }else if (i == 2)
            {
                c_Status_address = _address;
            }
        }
    }

    addressToWrite1 = (LPVOID)address1;
    addressToWrite2 = (LPVOID)address2;


    std::getline(patestFile, pattern);
    std::vector<BYTE> byte_pattern2 = hexStringToByteVector(pattern);


    while (true)
    {
        locValueFX = locValue % 65536;
        locValueFY = locValue / 65536;

        ReadProcessMemory(hProcess, check_address, &check, sizeof(check), NULL);

        if (check != 1 || (locValueFX == 27 || locValueFY == 27 || locValueFX == 0 || locValueFY == 0))
        {
            read_all_memory_loop(processID, byte_pattern2, outputFile, 0x14000000, address4, read_address);
        }
        
        address3 = read_address + 0x10;
        address4 = read_address - 0x108;
        address5 = read_address + 0x1D8;
        address6 = read_address + 0x18;
        address7 = write_address + 0xC;
        address8 = read_address - 0xE0;
        address9 = read_address - 0x04;

        addressToRead = (LPVOID)address3;
        check_address = (LPVOID)address4;
        is_combat = (LPVOID)address5;

        ReadProcessMemory(hProcess, check_address, &check, sizeof(check), NULL);


        //std::cout << "Address to read " << std::hex << addressToRead << " | Address to write :"<< write_address << " Check Value : "<< direction << std::endl;

        ReadProcessMemory(hProcess, (LPVOID)address9, &cHp, sizeof(cHp), NULL);
        ReadProcessMemory(hProcess, addressToRead, &valueToRead, sizeof(valueToRead), NULL);
        ReadProcessMemory(hProcess, is_combat, &isCombatValue, sizeof(isCombatValue), NULL);
        ReadProcessMemory(hProcess, (LPVOID)address6, &pCursorLoc, sizeof(pCursorLoc), NULL);
        ReadProcessMemory(hProcess, (LPVOID)address7, &cursorStatus, sizeof(cursorStatus), NULL);
        ReadProcessMemory(hProcess, (LPVOID)address8, &direction, 1, NULL);
        ReadProcessMemory(hProcess, (LPVOID)(loc_address + 0x10), &locValue, 1, NULL);
        ReadProcessMemory(hProcess, (LPVOID)c_Status_address, &cStatusValue, sizeof(cursorStatus), NULL);

        if (direction == 0) {
            dValue = 1;
        } else if (direction == 1)
        {
            dValue = -1;
        } else if (direction == 2)
        {
            dValue = 65536;
        } else if (direction == 3)
        {
            dValue = -65536;
        } else {
            dValue = 0;
        }

        valueToWrite = valueToRead + dValue;

        if (check == 0 && (locValueFX == 27 || locValueFY == 27 || locValueFX == 0 || locValueFY == 0))
        {
            std::cout << std::dec << "Cross Script " << locValueFX <<" | "<< locValueFY <<" | "<< locValue << " | "<< check << "                 \r";
            
            WriteProcessMemory(hProcess, (LPVOID)(write_address), &valueToRead, sizeof(valueToRead), NULL);
            WriteProcessMemory(hProcess, (LPVOID)(write_address - 100), &valueToRead, sizeof(valueToRead), NULL);
            
            if (check == 0 && (locValue % 65536 != 27 || locValue / 65536 != 27 || locValue % 65536 != 0 || locValue / 65536 != 0))
            {
                delay(50);
                sendKeyToWindow(hwnd, VK_RETURN);
            }
        } else if (check > 0 && isCombatValue == 0 && (locValueFX != 27 || locValueFY != 27 || locValueFX != 1 || locValueFY != 1 || valueToRead != 0)) {
            std::cout << std::dec << "Follow Script " << locValueFX <<" | "<< locValueFY <<" | "<< valueToRead << " | " << check << "                 \r";
            
            WriteProcessMemory(hProcess, (LPVOID)(write_address)      , &valueToWrite, sizeof(valueToWrite), NULL);
            WriteProcessMemory(hProcess, (LPVOID)(write_address - 100), &valueToWrite, sizeof(valueToWrite), NULL);


            if (cursorStatus == 13 && valueToWrite != locValue)
            {
                delay(50);
                sendKeyToWindow(hwnd, VK_RETURN);
            }
        }else if (check > 0 && isCombatValue != 0)
        {
            std::cout << std::dec << "Attack Script " << locValueFX <<" | "<< locValueFY <<" | "<< isCombatValue << " | " << check << "                 \r";

            valueToWrite = pCursorLoc;
            cValueToWrite1 = (pCursorLoc / 65536)* 1572864; //This is the equation to transfare X value
            cValueToWrite2 = (pCursorLoc % 65536)* 1572864; //This is the equation to transfare Y value
            
            WriteProcessMemory(hProcess, (LPVOID)(write_address), &valueToWrite, sizeof(valueToWrite), NULL);
            WriteProcessMemory(hProcess, (LPVOID)(write_address - 0x58), &cValueToWrite1, sizeof(cValueToWrite1), NULL);
            WriteProcessMemory(hProcess, (LPVOID)(write_address - 100), &valueToWrite, sizeof(valueToWrite), NULL);
            WriteProcessMemory(hProcess, (LPVOID)(write_address - 0x5C), &cValueToWrite2, sizeof(cValueToWrite2), NULL);

            delay(50);
            sendKeyToWindow(hwnd, VK_RETURN);
            delay(50);
            sendKeyToWindow(hwnd, 0x31);
        }
        //if (check == 1 && cHp < 4707)
        //{
        //    valueToWrite = valueToRead;
        //    cValueToWrite1 = (valueToRead / 65536)* 1572864; //This is the equatuon to transfare X value
        //    cValueToWrite2 = (valueToRead % 65536)* 1572864; //This is the equatuon to transfare Y value
        //    
        //    WriteProcessMemory(hProcess, (LPVOID)(write_address), &valueToWrite, sizeof(valueToWrite), NULL);
        //    WriteProcessMemory(hProcess, (LPVOID)(write_address - 0x58), &cValueToWrite1, sizeof(cValueToWrite1), NULL);
        //    WriteProcessMemory(hProcess, (LPVOID)(write_address - 100), &valueToWrite, sizeof(valueToWrite), NULL);
        //    WriteProcessMemory(hProcess, (LPVOID)(write_address - 0x5C), &cValueToWrite2, sizeof(cValueToWrite2), NULL);
        //    
        //    delay(50);
        //    sendKeyToWindow(hwnd, 0x35);
        //    delay(50);
        //    sendKeyToWindow(hwnd, VK_RETURN);
        //}
    }
    CloseHandle(hProcess);

    return 0;
}