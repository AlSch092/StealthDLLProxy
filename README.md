# StealthDLLProxy
Example of natural/unassisted DLL injection via proxying using various stealth techniques (Windows, x64, C Language)  

This project demonstrates an example of loading a DLL into a process without using an explicit injector. While DLL proxying is a well-known and traditional method of injection, this example adds in beneficial features that can assist with AV/AC evasion. It takes advantage of module load order, and hopes that the processes' code doesn't specify the full DLL path when loading a module.  

## How it works:
1. Our compiled module is named to some module loaded by our target process, in this case "msimg32.dll". It often saves time to pick a module with a relatively low number of exports.  

2. We place the compiled module in the same directory as the target process, taking advantage of the fact that by default this will be loaded before the real msimg32.dll (if a full path isn't used by the process)  

3. When the target process loads our module, we change our module's name in the LDR DATA TABLE to an empty string, which will cause most applications to see it as "null" and skip any sort of querying  

4. We then unlink our module from the PEB's LDR_DATA_TABLE, effectively removing it from the list of loaded modules.  

5. Finally, we load the real msimg32.dll from its original path by using `LoadLibraryW`. Exports are forwarded to the real msimg32.dll, so the target process can use them as if it was using the original   module, and everything appears normal.

6. The PE headers of our module are wiped to help prevent further analysis or detection.

## Techniques/features:
- When initially loaded into the process, the module renames itself in memory to 'null' (as in, a 0-length empty string, such as "") by manipulating its LDR_DATA table entry. This may cause AV/ACs to skip over it when scanning or querying, as it will appear to have a 'null' name.  
- Unlinks the module from the processes' module list (`InLoadOrderModuleList`, `InMemoryOrderLinks`)  
- Deletes the PE header of the module

What's left after applying these techniques is a group of sections unassociated with any named loaded module, appearing similar to a manually-mapped module which has had its PE headers removed. Unlike injection via manual mapping, no process handles are required for module loading, which means protected processes that block handle creation can still be loaded into, since the target process naturally loads the module. With that being said, it does not guarantee a specific process will or won't detect our module. The code can be taken further to encrypt & decrypt memory just-in-time using guard pages, or hidden with `PAGE_NOACCESS` page protections to avoid detection.  

## Example
In `DLLMain.cpp`, the example proxies 'msimg32.dll' which is normally found in the System32 folder. The target process tested on was Cheat Engine, since it loads this module when the process starts. If everything works fine, a message box should appear saying "Proxy injection was successful!".  
