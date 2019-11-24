### Injector

Injector module provides capability to run a DLL application on top of another process. Hence, the application process is hidden from Task Manager.

#### Usage Example

```
char dllPath[] = "absolute/path/to/app.dll";
DWORD keyloggerPID = Injector::inject("notepad.exe", absolutedll);
```