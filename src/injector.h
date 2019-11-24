#include <Windows.h>

class Implementation;

class Injector
{
  private:
    static Implementation *implementation;
  public:
  	static DWORD inject(char *, char *);
  	static DWORD inject(char *);
};
