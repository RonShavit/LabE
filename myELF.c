#include <stdlib.h>
#include <sys/mman.h>

/// @brief a single row in the printed menu
typedef struct menu_item
{
    char* text;//null-terminated string to be printed (minus number)
    void (*func)();//func to be activated of type ()=>void
}menu_item;

char debug_mode = 0;

/// @brief truns debug_mode on/off
void tgl_debug_mode()
{
    debug_mode = 1-debug_mode;
}

void exmn_elf_file()
{
    printf("NYI : exmn elf file\n");
}

void prnt_sectns_names()
{
    printf("NYE : prnt_sectns_names\n");
}

void prnt_sym()
{
    printf("NYE : prnt_sym\n");
}

void chk_files_for_mrg()
{
    printf("NYE : chk_files_for_mrg\n");
}

void mrg_elf_files()
{
    printf("NYE : mrg_elf_files\n");
}

void quit()
{
    printf("quitting...\n");
    
    exit(0);
}



menu_item* menu[7];
char* text_arr[] = {"Toggle Debug Mode", "Examine ELF File","Print Section Names","Print Symbols", "Check Files for Merge","Merge ELf Files","Quit"  };
void* func_arr[] = {tgl_debug_mode,exmn_elf_file,prnt_sectns_names,prnt_sym,chk_files_for_mrg,mrg_elf_files,quit};

void free_menu()
{
    for (int i=0;i<=6;i++)
    {
        free(menu[i]);
    }
    free(menu);
}

void make_menu()
{
    for (int i=0;i<=6;i++)
    {
        menu[i] = malloc(sizeof(menu_item));
        menu[i]->text = text_arr[i];
        menu[i]->func = func_arr[i];
    }
}


int main(int argc, char* argv[])
{
    make_menu();

    free_menu();
}

