# InjecTOR

## Purpose

InjecTOR is a Dynamic Link Library (DLL) injection application. The majority of techniques used to facilitate DLL injection on Windows is through the local user-mode API. While these techniques are effective, they are well-known and are detectable in many anti-reverse engineering systems.

InjecTOR is unique because it utilizies a kernel driver to facilitate the DLL injection. This way, the platform can discretely inject itself into the target application without being detected by anti-hacking systems.

## How it works

The injection is a three-step process which is compatible for every application:

  1. After the driver loads, it attaches itself to the target application's memory space using KeStackAttachProcess()
  2. The driver sets up a Ring3 hook on a commonly invoked function like Sleep()
  3. The driver forces the application to call LoadLibrary() on the the DLL
  4. After injection, the hook on removed and the driver detaches itself

## Disclaimer

Make sure to disable driver certification checks in order to run the application!

Use at your own risk!
