Welcome to HookFunction
=======================

This is the source code page for the **HookFunction**.  With the source code, you can modify the tool in any way imaginable and share your changes with others!

Source releases
---------------

We recommend you work with a versioned release. The master branch contains unstable and possibly untested code, but it should be a great reference for new developments, or for spot merging bug fixes. Use it at your own risk.  

Getting up and running
----------------------

Here is the fun part!  This is a quick start guide to getting up and running with the source.  The steps below will take you through cloning your own private fork, then compiling and 
running the editor yourself on Windows other platforms will be implemented at a later point in time.  Okay, here we go!

1. We recommend using Git in order to participate in the community, but you can **download the source** as a zip file if you prefer. See instructions for 
   [setting up Git](http://help.github.com/articles/set-up-git), then [fork our repository](https://help.github.com/articles/fork-a-repo), clone it to your local machine.
   
2. You should now have an **HookFunction** folder on your computer.  All of the source and dependencies will go into this folder.  The folder name might have a branch suffix, but that's fine.

3. Okay, platform stuff comes next.  Depending on whether you are on Windows or another platform, follow one of the sections below.

## Windows

4. Be sure to have [Visual Studio 2013](http://www.microsoft.com/en-us/download/details.aspx?id=40787) installed.  You can use any 
   desktop version of Visual Studio 2013, including the free version:  [Visual Studio 2013 Express for Windows Desktop](http://www.microsoft.com/en-us/download/details.aspx?id=40787)

5. Load the project into Visual Studio by double-clicking on the **HookFunction.sln** file.

6. It's time to **compile the editor**!  In Visual Studio, make sure your solution configuration is set to **Release**, and your solution 
   platform is set to **x64** or **Win32** depending on your needs. Locate and click **Build** in your toolbar. A new menu should open allowing you to click *Build solution**

7. After compiling finishes the program is ready to use!

### Additional target platforms

Currently not supported.

Usage
-----

The **HookFunction** program consists out of a executable and a DLL. The executable will inject the DLL into the remote process and invoke the DLL functions with the specified parameters. The DLL will then load the required DLL's to execute the function specified through parameters. **HookFunction** is made to hook arbitrary functions and it allows for easy proxy function injection.

Example
-------

The following command will hook a function in the program **InterceptMe.exe** at the relative virtual address **0x11177** to InterceptMe.exe (second parameter). This relative virtual address indicates the address of the **RC4** cryptography function. Then the path to the DLL containing the proxy function is given. The last parameter is the name of the proxy function to invoke. The full command is shown below:

```
HookFunction InterceptMe.exe InterceptMe.exe 0x11177 "X:\...\HookInterceptMe.DLL" ProxyRC4
HookFunction Executable      Module          Offset  HookDll                      ProxyFunctionName
```

An example proxy DLL is shown below:

```c
#include <Windows.h>
#include <stdio.h>
#include <map>

//A map containing the mapping of the proxy function address to the original function address
std::map<void*, void*> _originalFunctionMap;

//The proxy function
extern "C" _declspec(DLLexport) void ProxyRC4(const char* input, int inputLength, const char* key, int keyLength, char* output)
{
	printf("InterceptMe called ProxyRC4(%s, %i, %s, %i, %08X)\r\n", input, inputLength, key, keyLength, output);

	//Call the original function
	std::map<void*, void*>::iterator itr = _originalFunctionMap.find((void*)&ProxyRC4);
	if (itr != _originalFunctionMap.end())
		((void (*)(const char*, int, const char*, int, char*))itr->second)(input, inputLength, key, keyLength, output);
}

//Gets invoked to map the proxy function addres to the original function address
extern "C" _declspec(DLLexport) void SetOriginalFunctionMapping(void* from, void* to)
{
	_originalFunctionMap[from] = to;
}

BOOL WINAPI DllMain(HINSTANCE module_handle, DWORD reason_for_call, LPVOID reserved)
{
	return TRUE;
}
```

Every time the **RC4** function in the program will be invoked our program will intercept the code flow. This allows us to do tampering before encryption and after decryption.

Using [HookPython](https://git.koenj.com/koenj/hookpython) it is possible to make python proxy functions. If you want to know more please visit the [HookPython](https://git.koenj.com/koenj/hookpython) page.

Special Case
------------

The function name **PythonHook** is used as a keyword to detect when python hooking is requested. If you want to know more please visit [HookPython](https://git.koenj.com/koenj/hookpython).

Additional Notes
----------------

Visual Studio 2013 is strongly recommended for compiling.

The first time you start the editor from a fresh source build, you may experience long load times.  This only happens on the first run.