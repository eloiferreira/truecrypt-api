// ApiTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "..\Common\Options.h"

using namespace std;

typedef BOOL (STDMETHODCALLTYPE *PINITIALIZE)(PTCAPI_OPTIONS options);
typedef int (STDMETHODCALLTYPE *PLOAD_TC_DRIVER)();

class ApiTest {
private:
	HMODULE hApiDll;
	PLOAD_TC_DRIVER LoadTrueCryptDriver;
	PINITIALIZE Initialize;
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
			cout << "TrueCryptApi dll has not been initialized" << endl;
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

		LoadProcAddress((FARPROC *)&LoadTrueCryptDriver, "LoadTrueCryptDriver");
		LoadProcAddress((FARPROC *)&Initialize, "Initialize");

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

public:
	void run() {
		if (!LoadTrueCryptApi(L"TrueCryptApi.dll")) return;
		if (GetApiAddresses()) {
			cout << "Initializing" << endl;
			Initialize(NULL);
			cout << "Initialize returned " << endl;
			
			cout << "Loading TrueCrypt Driver" << endl;
			int res = LoadTrueCryptDriver();
			cout << "LoadTrueCryptDriver returned " << res << endl;
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

