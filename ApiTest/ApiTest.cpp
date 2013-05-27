// ApiTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "..\Common\Options.h"
#include "..\Common\Password.h"

using namespace std;

typedef BOOL (STDMETHODCALLTYPE *PINITIALIZE)(PTCAPI_OPTIONS options);
typedef int (STDMETHODCALLTYPE *PSHUTDOWN)();
typedef int (STDMETHODCALLTYPE *PLOAD_TC_DRIVER)();
typedef int (STDMETHODCALLTYPE *PUNLOAD_TC_DRIVER)();
typedef BOOL (STDMETHODCALLTYPE *PMOUNT)(int nDosDriveNo, char *szFileName, Password VolumePassword);

class ApiTest {
private:
	HMODULE hApiDll;
	PLOAD_TC_DRIVER LoadTrueCryptDriver;
	PUNLOAD_TC_DRIVER UnloadTrueCryptDriver;
	PINITIALIZE Initialize;
	PSHUTDOWN Shutdown;
	PMOUNT Mount;

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
		LoadProcAddress((FARPROC *)&UnloadTrueCryptDriver, "UnloadTrueCryptDriver");
		LoadProcAddress((FARPROC *)&Mount, "MountV");

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
		int numOptions = 6;

		DWORD memSize = sizeof TCAPI_OPTIONS + (sizeof TCAPI_OPTION * numOptions);

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

		pOptions->Options[4].OptionId = TC_OPTION_DRIVER_PATH;
		pOptions->Options[4].OptionValue = NULL; //(DWORD) &"D:\\Projects\\Active\\truecrypt-x64.sys";

		pOptions->Options[5].OptionId = TC_OPTION_WIPE_CACHE_ON_EXIT;
		pOptions->Options[5].OptionValue = TRUE;
		
		pOptions->NumberOfOptions = numOptions;

		cout << "Initializing" << endl;
		BOOL res = Initialize(pOptions);
		
		free(pOptions);
		
		cout << "Initialize returned " << res << endl;
	}

	void RunShutdown() {
		cout << "Unloading driver" << endl;
		BOOL res = UnloadTrueCryptDriver();
		cout << "UnloadTrueCryptDriver returned " << res << endl;

		cout << "Shutting down" << endl;
		res = Shutdown();
		cout << "Shutdown returned " << res << endl;
	}

	void RunMount() {
		Password pass;
		const char *passString = "lalala";
		memset(&pass, 0, sizeof pass);
		
		pass.Length = strlen(passString);
		strcpy ((char *) &pass.Text[0], passString);

		cout << "Mounting volume" << endl;

		BOOL res = Mount(15, "d:\\test.dat", pass);

		cout << "Volume mount result: " << res << endl;

	}

public:
	void run() {
		if (!LoadTrueCryptApi("TrueCryptApi.dll")) return;
		if (GetApiAddresses()) {
			RunInitialize();

			cout << "Loading TrueCrypt Driver" << endl;
			int res = LoadTrueCryptDriver();
			if (res == 0) {
				cout << "Error loading TrueCrypt driver: " << hex << GetLastError() << endl;
			} else {
				cout << "LoadTrueCryptDriver version: " << hex << res << endl;
			}

			RunMount();

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

