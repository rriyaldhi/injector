#include "injector.h"
#include "implementation.h"

Implementation *Injector::implementation;

DWORD Injector::inject(char *process, char *buffer)
{
  return Injector::implementation->inject(process, buffer);
}

DWORD Injector::inject(char *buffer)
{
  return Injector::implementation->inject(NULL, buffer);
}