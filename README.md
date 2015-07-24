This is the driver that preforms the injection. The injection is a three-step process which works for every application and its
as follows:

  1. Attach to the process by calling KeStackAttachProcess ()
  2. Hook a commonly called function such as Sleep () and force LoadLibrary() to be called 
  3. After the injection is successful remove the hook on Sleep () and free allocated memory
