#include <shlwapi.h>
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

#include "hook/procaddr.h"

#include "hook/table.h"

static struct proc_addr_table *proc_addr_hook_list;
static size_t proc_addr_hook_count;
static CRITICAL_SECTION proc_addr_hook_lock;
static bool proc_addr_hook_initted;

static FARPROC WINAPI my_GetProcAddress(HMODULE hModule, const char *name);
static FARPROC (WINAPI *next_GetProcAddress)(HMODULE hModule, const char *name);
static void proc_addr_hook_init();

static const struct hook_symbol win32_hooks[] = {
    {
        .name = "GetProcAddress",
        .patch = my_GetProcAddress,
        .link = (void **) &next_GetProcAddress
    }
};

HRESULT proc_addr_table_push(
    HMODULE loader_mod,
    const char *target,
    const struct hook_symbol *syms,
    size_t nsyms
)
{
    HRESULT hr;
    struct proc_addr_table *new_item;
    struct proc_addr_table *new_mem;

    proc_addr_hook_init();

    proc_addr_insert_hooks(loader_mod);

    EnterCriticalSection(&proc_addr_hook_lock);

    new_mem = realloc(
            proc_addr_hook_list,
            (proc_addr_hook_count + 1) * sizeof(struct proc_addr_table));
    
    if (new_mem == NULL) {
        hr = E_OUTOFMEMORY;
        
        LeaveCriticalSection(&proc_addr_hook_lock);
        return hr;
    }

    new_item = &new_mem[proc_addr_hook_count];
    new_item->name = target;
    new_item->nsyms = nsyms;
    new_item->syms = (struct hook_symbol *) syms;

    proc_addr_hook_list = new_mem;
    proc_addr_hook_count++;
    hr = S_OK;

    LeaveCriticalSection(&proc_addr_hook_lock);

    return hr;
}

void proc_addr_insert_hooks(HMODULE target)
{
    hook_table_apply(
            target,
            "kernel32.dll",
            win32_hooks,
            _countof(win32_hooks));
}

static void proc_addr_hook_init(void)
{
    if (proc_addr_hook_initted) {
        return;
    }

    proc_addr_hook_initted = true;

    InitializeCriticalSection(&proc_addr_hook_lock);
}

FARPROC WINAPI my_GetProcAddress(HMODULE hModule, const char *name)
{
    uintptr_t ordinal = (uintptr_t) name;
    char mod_path[MAX_PATH];
    const struct hook_symbol *sym;
    FARPROC result = next_GetProcAddress(hModule, name);
    
    GetModuleFileNameA(hModule, mod_path, MAX_PATH);
    PathStripPathA(mod_path);
    
    for (int i = 0; i < proc_addr_hook_count; i++) {

        if (strcmp(proc_addr_hook_list[i].name, mod_path) == 0) {
            
            for (int j = 0; j < proc_addr_hook_list[i].nsyms; j++) {
                sym = &proc_addr_hook_list[i].syms[j];
                
                if (ordinal > 0xFFFF) {

                    if (strcmp(sym->name, name) == 0) {
                        result = (FARPROC) sym->patch;
                    }
                }

                else {
                    if (sym->ordinal == ordinal) {
                        result = (FARPROC) sym->patch;
                    }
                }
            }
        }
    }

    return result;
}
