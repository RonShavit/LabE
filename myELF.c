#include <stdlib.h>
#include <sys/mman.h>

typedef struct menu_item
{
    char* text;
    void (*func)();
}menu_item;