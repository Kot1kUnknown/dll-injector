#include <iostream>
#include <Windows.h>

int InjectDLL(DWORD, char*);
int DLLpath(char*);
int PID(int*);
int Process(HANDLE*, DWORD);

int DLLpath(char* dll)
{
    std::cout << "Enter dll path: ";
    std::cin >> dll;
    return 1;
}

int PID(int* pid)
{
    std::cout << "Enter process PID: ";
    std::cin >> *pid;
    return 1;
}

int Process(HANDLE* handleToProcess, DWORD pid)
{
    *handleToProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    DWORD Erros;


    if (*handleToProcess == NULL)
    {
        std::cout << "Failed to open the process... :(";
        return -1;
    }
    else
    {
        std::cout << "The process has been opened successfully.. :)";
        return 1;
    }
}

int InjectDLL(DWORD pid, char* dll)
{
    HANDLE handleToProcess;
    LPVOID LoadLibAddr;
    LPVOID baseAddr;
    HANDLE rThread;

    // Получаем длину библиотеки

    int dllLength = strlen(dll) + 1;

    // Получаем обработку процесса
    if (Process(&handleToProcess, pid) < 0)
    {
        return -1;
    }

    // Загружаем kernal32.dll (библиотека)(
    LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernal32.dll"), "LoadLibA");

    if (!LoadLibAddr)
    {
        return -1;
    }

    baseAddr = VirtualAllocEx(handleToProcess, NULL, dllLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!baseAddr)
    {
        return -1;
    }

    // Записываем путь к dll
    if (!WriteProcessMemory(handleToProcess, baseAddr, dll, dllLength, NULL))
    {
        return -1;
    }

    // Создаем поток
    rThread = CreateRemoteThread(handleToProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, baseAddr, 0, NULL);

    if (!rThread)
    {
        return -1;
    }

    // Ждем освобождения памяти
    WaitForSingleObject(rThread, INFINITY);

    VirtualFreeEx(handleToProcess, baseAddr, dllLength, MEM_RELEASE);

    // Закрываем обработчик
    if (CloseHandle(rThread) == 0)
    {
        std::cout << "Error closing the remote process... :(";
        return -1;
    }

    if (CloseHandle(handleToProcess) == 0)
    {
        std::cout << "Failed to close target handle... :(";
        return -1;
    }
}

int main()
{
    char* dll = new char[255];
    int pid = -1;

    DLLpath(dll);
    PID(&pid);

    InjectDLL(pid, dll);

    std::cout << "\nCoded by shurup.";
    system("pause");
    return 0;
}