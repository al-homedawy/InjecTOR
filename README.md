InjecTOR-Driver

  This is the driver that preforms the injection. The injection is a four-step process which works for every application and its
as follows:

  1. Attach to the process using KeStackAttachProcess
  2. Allocate memory within the application and then write the injection-code
  3. Hook a commonly called function such as Sleep () and call the newly-allocated function.
  4. After the injection remove the hook on Sleep () and free the allocated pages.
  
  The driver certification for the drivers is expired, you can certify it on your own time. The driver supports most operating
systems including Windows 8.1. The main factor seperating each operating system is the location of the unreferenced yet 
neccessary function ZwAllocateVirtualMemory. Its position in memory differs from operating system to operating system.
