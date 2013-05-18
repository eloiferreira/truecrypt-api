// ApiTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "..\Common\Options.h"

using namespace std;

typedef BOOL (STDMETHODCALLTYPE *PINITIALIZE)(PTCAPI_OPTIONS options);
typedef int (STDMETHODCALLTYPE *PSHUTDOWN)();
typedef int (STDMETHODCALLTYPE *PLOAD_TC_DRIVER)();

class ApiTest {
private:
	HMODULE hApiDll;
	PLOAD_TC_DRIVER LoadTrueCryptDriver;
	PINITIALIZE Initialize;
	PSHUTDOWN Shutdown;

protected:
	BOOL LoadTrueCryptApi(LPCTSTR path) {
		wcout << "Loading TrueCrypt API dll from " << path << endl;
		hApiDll = LoadLibrary(path);
		if (!hApiDll) {
			cout << "Error loading TrueCrypt API dll: " << GetLastError() << endl;
		} else {
			cout << "Loaded successfully" << endl;
		}
		return (BOOL) hApiDll;
	}

	BOOL UnloadTrueCryptApi() {
		cout << "Unloading TrueCrypt API dll" << endl;
		if (!hApiDll) {
			cout << "TrueCryptApi dll has not been loaded" << endl;
			return FALSE;
		}

		if (FreeLibrary(hApiDll)) {
			hApiDll = NULL;
			cout << "Unloaded\n";
			return TRUE;
		} else {
			cout << "Error unloading TrueCrypt API dll: " << GetLastError() << endl;
			return FALSE;
		}
	}

	BOOL GetApiAddresses() {
		cout << "Getting API addresses" << endl;
		if (!hApiDll) {
			cout << "TrueCryptApi dll has not been initialized" << endl;
			return FALSE;
		}

		LoadProcAddress((FARPROC *)&Initialize, "Initialize");
		LoadProcAddress((FARPROC *)&Shutdown, "Shutdown");
		LoadProcAddress((FARPROC *)&LoadTrueCryptDriver, "LoadTrueCryptDriver");

		return TRUE;
	}

	void LoadProcAddress(FARPROC *proc, char *name) {
		*proc = GetProcAddress(hApiDll, name);
		if (!proc) {
			cout << "Error getting address of " << name << ": " << GetLastError() << endl;
			return;
		} else {
			cout << name << " loaded at: " << proc << endl;
		}
	}

	void RunInitialize() {
		PTCAPI_OPTIONS pOptions;
		DWORD memSize = sizeof TCAPI_OPTIONS + (sizeof TCAPI_OPTION * 4);

		pOptions = (PTCAPI_OPTIONS) malloc(memSize);
		memset(pOptions, 0, memSize);
		
		pOptions->Options[0].OptionId = TC_OPTION_PRESERVE_TIMESTAMPS;
		pOptions->Options[0].OptionValue = TRUE;

		pOptions->Options[1].OptionId = TC_OPTION_CACHE_PASSWORDS;
		pOptions->Options[1].OptionValue = TRUE;

		pOptions->Options[2].OptionId = TC_OPTION_MOUNT_READONLY;
		pOptions->Options[2].OptionValue = TRUE;

		pOptions->Options[3].OptionId = TC_OPTION_MOUNT_REMOVABLE;
		pOptions->Options[3].OptionValue = TRUE;

		pOptions->NumberOfOptions = 4;

		cout << "Initializing" << endl;
		BOOL res = Initialize(pOptions);
		
		free(pOptions);
		
		cout << "Initialize returned " << res << endl;
	}

	void RunShutdown() {
		cout << "Shutting down" << endl;
		BOOL res = Shutdown();
		cout << "Shutdown returned " << res << endl;
	}

public:
	void run() {
		if (!LoadTrueCryptApi(L"TrueCryptApi.dll")) return;
		if (GetApiAddresses()) {
			RunInitialize();

			cout << "Loading TrueCrypt Driver" << endl;
			int res = LoadTrueCryptDriver();
			cout << "LoadTrueCryptDriver returned " << res << endl;

			RunShutdown();
		}
		UnloadTrueCryptApi();
	}
};

int _tmain(int argc, _TCHAR* argv[])
{
	ApiTest *apiTest = new ApiTest();
	apiTest->run();
	delete apiTest;
	cin.get();
	return 0;
}

