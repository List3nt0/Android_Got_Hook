#include <unistd.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <android/log.h>  
#include <elf.h>  
#include <fcntl.h>  
#include <sys/mman.h>
//#include <linker.h>
#include <dlfcn.h>
#include <EGL/egl.h>  
#include <GLES/gl.h>

#define LOG_TAG "HOOK"  
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)    

extern "C" {
//external function declaration
//extern void print();

//void (*print)();

/*void newPrint()  
{  
    LOGD("new Print\n");
    print();
}
*/

EGLBoolean (*old_eglSwapBuffers)(EGLDisplay dpy, EGLSurface surf) = NULL;  
  
EGLBoolean new_eglSwapBuffers(EGLDisplay dpy, EGLSurface surface)  
{  
    LOGD("New eglSwapBuffers\n");  
    if (old_eglSwapBuffers == NULL)  
        LOGD("error\n");  
    return old_eglSwapBuffers(dpy, surface);  
}

//------------
// Extracted from android linker
//------------
// Magic shared structures that GDB knows about.

typedef struct link_map_t {
  uintptr_t l_addr;
  char*  l_name;
  uintptr_t l_ld;
  struct link_map_t* l_next;
  struct link_map_t* l_prev;
} link_map_t;

typedef void (*linker_function_t)();

#define SOINFO_NAME_LEN 128
typedef struct soinfo {
    char name[SOINFO_NAME_LEN];
    const Elf_Phdr* phdr;
    size_t phnum;
    Elf_Addr entry;
    Elf_Addr base;
    unsigned size;

    uint32_t unused1;  // DO NOT USE, maintained for compatibility.

    Elf_Dyn* dynamic;

    uint32_t unused2; // DO NOT USE, maintained for compatibility
    uint32_t unused3; // DO NOT USE, maintained for compatibility

    struct soinfo* next;

    unsigned flags;

    const char* strtab;
    Elf_Sym* symtab;
    size_t nbucket;
    size_t nchain;
    unsigned* bucket;
    unsigned* chain;

	//------------------

  // This is only used by 32-bit MIPS, but needs to be here for
  // all 32-bit architectures to preserve binary compatibility.
  unsigned* plt_got;

  Elf_Rel* plt_rel;
  size_t plt_rel_count;

  Elf_Rel* rel;
  size_t rel_count;

  linker_function_t* preinit_array;
  size_t preinit_array_count;

  linker_function_t* init_array;
  size_t init_array_count;
  linker_function_t* fini_array;
  size_t fini_array_count;

  linker_function_t init_func;
  linker_function_t fini_func;

  // ARM EABI section used for stack unwinding.
  unsigned* ARM_exidx;
  size_t ARM_exidx_count;

  size_t ref_count;
  link_map_t link_map;

  int constructors_called;

  // When you read a virtual address from the ELF file, add this
  // value to get the corresponding address in the process' address space.
  Elf_Addr load_bias;

} soinfo;

#define LIBSF_PATH      "/system/lib/libsurfaceflinger.so"
#define FUNCTIONNAME    "eglSwapBuffers" 

void replaceFunc(void *handle,const char *name, void* pNewFun, void** pOldFun)  
{  

    if(!handle)
    return;
     
    soinfo *si = (soinfo*)handle;     
    Elf32_Sym *symtab = si->symtab;    
    const char *strtab = si->strtab;    
    Elf32_Rel *rel = si->plt_rel;  
    unsigned count = si->plt_rel_count;   
    unsigned idx;   

    bool fit = 0;

    for(idx=0; idx<count; idx++)   
    {    
        unsigned int type = ELF32_R_TYPE(rel->r_info);    
        unsigned int sym = ELF32_R_SYM(rel->r_info);    
        unsigned int reloc = (unsigned)(rel->r_offset + si->base);    
        char *sym_name = (char *)(strtab + symtab[sym].st_name);   

        if(strcmp(sym_name, name)==0)   
        {   
        		
            uint32_t page_size = getpagesize();  
            uint32_t entry_page_start = reloc& (~(page_size - 1));  
            mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
						
            *pOldFun = (void *)*((unsigned int*)reloc);																//pOldFun = &g_OriginalFunc *pOldFun = g_OriginalFunc
            *((unsigned int*)reloc)= (unsigned int)pNewFun;
            LOGD("find %s function at address: %p\n",name,(void*)*pOldFun);
            fit = 1;
            break;
        }   
        rel++;    
    }  

    if(!fit) {
        LOGD("not find :%s in plt_rel\n",FUNCTIONNAME);
    }
} 




int hook()                                                  
{   
		LOGD("hooking\n");
		void *handle =  dlopen( LIBSF_PATH, RTLD_GLOBAL );	                                                                                                       
    //replaceFunc(handle,FUNCTIONNAME, g_NewFunc, (void**)&g_OriginalFunc);
    replaceFunc(handle,FUNCTIONNAME, (void*)&new_eglSwapBuffers, (void**)&old_eglSwapBuffers);
    return 0;                                                       
}                                                               

int hook_entry(char * a) {
	  LOGD("hook_entry");  
    hook();
    return 0;  
}

}
