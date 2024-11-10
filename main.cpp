#include <fstream>
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <string>
#include <thread>
#include <chrono>


using namespace std;

int InjectDLL(DWORD, char*);
int getDLLpath(char*);
int getProc(HANDLE*, DWORD);

int getDLLpath(char* dll)
{
	std::cout << "Please enter the path to your DLL file\n";
	cin >> dll;
	//char path[] = "C:/hobbit.dll";
	//dll = path;
	return 1;
}

int GetProcessIDByName(const std::wstring& processName) {
	DWORD pid = 0;     //переменная айди процесса
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(snapshot, &pe32)) {
		while (Process32Next(snapshot, &pe32)) { //ищет айди процесса
			if (_wcsicmp(pe32.szExeFile, L"Meridian.exe") == 0) {
				pid = pe32.th32ProcessID; //переменная айди процесса
				break;
			}
		}
	}
	std::cout << pid << "\n";
	return pid;
}



int getProc(HANDLE* handleToProc, DWORD pid)
{
	*handleToProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	DWORD dwLastError = GetLastError();

	if (*handleToProc == NULL)
	{
		std::cout << "Unable to open process. Error code: " << dwLastError << "\n";
		return -1;
	}
	else
	{
		std::cout << "Process Opened.\n";
		return 1;
	}
}

bool ResolveFullPath(const char* relativePath, char* fullPath, DWORD fullPathSize) {
	return GetFullPathNameA(relativePath, fullPathSize, fullPath, NULL) != 0;
}



int InjectDLL(DWORD PID, const char* dll) {
	HANDLE handleToProc;
	LPVOID LoadLibAddr;
	LPVOID baseAddr;
	HANDLE remThread;

	// Resolve full path to DLL
	char fullPath[MAX_PATH];
	if (GetFullPathNameA(dll, MAX_PATH, fullPath, NULL) == 0) {
		std::cerr << "Failed to resolve full path for DLL." << std::endl;
		return -1;
	}

	std::ifstream file(fullPath);

	if (!file) {
		cout << fullPath << '\n';
		std::cout << "Can't find a dll file: " << fullPath << '\n';
		std::cout << "Aborting..." << '\n';
		return -1;
	}
	else cout << "dll found\n";

	// Get length of the full path
	int dllLength = strlen(fullPath) + 1;

	// Process handling
	if (getProc(&handleToProc, PID) < 0)
		return -1;

	// Load kernel32.dll
	LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (!LoadLibAddr)
		return -1;

	// Allocate memory in the process for the DLL path
	baseAddr = VirtualAllocEx(handleToProc, NULL, dllLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!baseAddr)
		return -1;

	// Write the DLL path to the allocated memory in the target process
	if (!WriteProcessMemory(handleToProc, baseAddr, fullPath, dllLength, NULL))
		return -1;

	// Create a remote thread in the target process to load the DLL
	remThread = CreateRemoteThread(handleToProc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibAddr, baseAddr, 0, NULL);
	if (!remThread)
		return -1;

	// Wait for the remote thread to finish
	WaitForSingleObject(remThread, INFINITE);

	// Free allocated memory in the target process
	VirtualFreeEx(handleToProc, baseAddr, dllLength, MEM_RELEASE);

	// Close handles
	if (CloseHandle(remThread) == 0) {
		std::cerr << "Failed to close handle to remote thread." << std::endl;
		return -1;
	}

	if (CloseHandle(handleToProc) == 0) {
		std::cerr << "Failed to close handle to process." << std::endl;
		return -1;
	}

	return 1;
}

int main()
{
	SetConsoleTitle(L"Inject");

	int PID = GetProcessIDByName(L"Meridian.exe");
	const char* dllPath = "./hobbit.dll";

	if (PID == 0)
	{
		cout << "The process cannot be found\nPlease run the target process before injecting\nAborting...";
		return 0;
	}
	if (InjectDLL(PID, dllPath) < 0)
	{
		std::cout << "DLL injection failed.\n";
		system("Pause");
	}
	else
	{
		std::cout << "DLL injection succeeded.\n";
		std::this_thread::sleep_for(std::chrono::seconds(5));
	}


	return 0;
}