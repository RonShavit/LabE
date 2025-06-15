#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>

#define FILES_COUNT 2

char *print_elf_data_format_string = "%-36s %s\n";
char *print_elf_data_format_hex = "%-36s %#x\n";
char *print_elf_data_format_chars = "%-36s %c%c%c\n";
char *print_elf_data_format_off = "%-36s %d (bytes into file)\n";
char *print_elf_data_format_dec = "%-36s %d\n";
char *print_elf_data_format_bytes = "%-36s %d|%#x (bytes)\n";

char *print_sections_format = "[%2d] %-25s %0#10x %0#8x %0#8x %s\n";

char *print_sym_format = "[%2d] %#010x %3s %-25s %s\n";

/// @brief a single row in the printed menu
typedef struct menu_item
{
    char *text;     // null-terminated string to be printed (minus number)
    void (*func)(); // func to be activated of type ()=>void
} menu_item;

typedef struct mapped_file
{
    char mapped;
    int fd;
    void *map_start;
    int size;
    char *name;

} mapped_file;

typedef struct sym_simple
{
    char *name;
    int section_index;
    struct sym_simple *next;
} sym_simple;

mapped_file *files[FILES_COUNT];

char debug_mode = 0;

/// @brief truns debug_mode on/off
void tgl_debug_mode()
{
    debug_mode = 1 - debug_mode;
    printf("Debug mode is now ");
    printf(debug_mode ? "on\n\n" : "off\n\n");
}

void print_elf_data(int i, char *name)
{
    Elf32_Ehdr *header = (Elf32_Ehdr *)files[i]->map_start;
    if (header->e_ident[0] == 0x7f && header->e_ident[1] == 'E' && header->e_ident[2] == 'L' && header->e_ident[3] == 'F')
    {
        printf("\"%s\"", name);
        printf("\n");
        printf(print_elf_data_format_chars, "id bytes: ", header->e_ident[1], header->e_ident[2], header->e_ident[3]);
        printf(print_elf_data_format_string, "Data encoding: ", header->e_ident[5] == 2 ? "2's complement, Big endian" : (header->e_ident[5] == 1 ? "2's complement, little endian" : "invalid data encodeing"));
        printf(print_elf_data_format_hex, "Entry point: ", header->e_entry);
        printf(print_elf_data_format_off, "Section header table offset:", header->e_shoff);
        printf(print_elf_data_format_dec, "Number of section header entries:", header->e_shnum);
        printf(print_elf_data_format_bytes, "Size of section header table entry:", header->e_shentsize, header->e_shentsize);
        printf(print_elf_data_format_off, "Program header table offset:", header->e_phoff);
        printf(print_elf_data_format_dec, "Number of program header entries:", header->e_phnum);
        printf(print_elf_data_format_bytes, "Size of program header table entry:", header->e_phentsize, header->e_phentsize);
        printf("\n");
    }
    else
    {
        fprintf(stderr, "ERROR : file %s is not a valid ELF\n", name);
    }
}

void exmn_elf_file()
{
    char *file_name[FILES_COUNT];
    char *input = malloc(128);
    for (int i = 0; i < FILES_COUNT; i++)
    {
        file_name[i] = malloc(128);
    }

    char found_free_space = 0;
    int fd;
    void *map_start;
    int size;

    printf("input name(s) of elf files\n");
    fgets(input, 128, stdin);
    sscanf(input, "%s %s", file_name[0], file_name[1]);

    for (int i = 0; i <= 1; i++)
    {
        found_free_space = 0;
        if (*file_name[i] != 0)
        {
            for (int j = 0; j < FILES_COUNT && found_free_space == 0; j++)
            {
                if (files[j]->mapped == 0)
                {
                    found_free_space = 1;
                    fd = open(file_name[i], O_RDWR);
                    if (fd < 0)
                    {
                        printf("ERROR : error opening file %s\n", file_name[i]);
                    }
                    else
                    {
                        lseek(fd, 0, SEEK_SET);
                        size = lseek(fd, 0, SEEK_END);
                        lseek(fd, 0, SEEK_SET);

                        files[j]->fd = fd;
                        map_start = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);

                        if (errno)
                        {
                            perror("ERROR");
                            close(fd);
                        }
                        else
                        {
                            files[j]->map_start = map_start;
                            files[j]->mapped = 1;
                            files[j]->size = size;
                            files[j]->name = file_name[i];
                            print_elf_data(j, file_name[i]);
                        }
                    }
                }
            }
            if (!found_free_space)
            {
                printf("ERROR : exceeded max number of mapped files (%d)\n", FILES_COUNT);
            }
        }
    }
    free(input);
}

void prnt_sectns_names()
{
    for (int i = 0; i < FILES_COUNT; i++)
    {
        if (files[i]->mapped)
        {
            printf("\"%s\"\n", files[i]->name);
            Elf32_Ehdr *header = (Elf32_Ehdr *)(files[i]->map_start);
            Elf32_Shdr *shdr_table = (Elf32_Shdr *)(((char *)(files[i]->map_start)) + (header)->e_shoff);

            Elf32_Shdr *sh_strtab_hdr = &shdr_table[header->e_shstrndx];
            const char *sh_strtab = (const char *)files[i]->map_start + sh_strtab_hdr->sh_offset;
            for (int j = 0; j < header->e_shnum; j++)
            {
                Elf32_Shdr *shdr = &shdr_table[j];
                const char *section_name = sh_strtab + shdr->sh_name;
                char *type;
                switch (shdr->sh_type)
                {
                case SHT_NULL:
                    /* code */
                    type = "NULL";
                    break;
                case SHT_DYNAMIC:
                    type = "DYNAMIC";
                    break;
                case SHT_PROGBITS:
                    type = "PROGBITS";
                    break;
                case SHT_SYMTAB:
                    type = "SYMTAB";
                    break;
                case SHT_NOTE:
                    type = "NOTE";
                    break;
                case SHT_SHLIB:
                    type = "SHLIB";
                    break;
                case SHT_STRTAB:
                    type = "STRTAB";
                    break;
                case SHT_RELA:
                    type = "RELA";
                    break;
                case SHT_HASH:
                    type = "HASH";
                    break;
                case SHT_NOBITS:
                    type = "NOBITS";
                    break;
                case SHT_REL:
                    type = "REL";
                    break;

                case SHT_GNU_versym:
                    type = "VERSYM";
                    break;
                case SHT_GNU_verneed:
                    type = "VERNEED";
                    break;
                case SHT_GNU_verdef:
                    type = "VERDEF";
                    break;

                case SHT_DYNSYM:
                    type = "DYNSYM";
                    break;

                default:
                    type = "UNKNOWN";
                    break;
                }

                printf(print_sections_format, j, section_name, shdr->sh_addr, shdr->sh_offset, shdr->sh_size, type);
            }
            printf("\n\n");
        }
    }
}

void prnt_sym()
{
    for (int i = 0; i < FILES_COUNT; i++)
    {
        if (files[i]->mapped)
        {
            printf("File ELF - %s\n", files[i]->name);
            Elf32_Ehdr *header = (Elf32_Ehdr *)(files[i]->map_start);
            Elf32_Shdr *shdr_table = (Elf32_Shdr *)(((char *)(files[i]->map_start)) + (header)->e_shoff);

            Elf32_Shdr *sh_strtab_hdr = &shdr_table[header->e_shstrndx];
            const char *sh_strtab = (const char *)files[i]->map_start + sh_strtab_hdr->sh_offset;
            for (int j = 0; j < header->e_shnum; j++)
            {
                char buff[10];
                Elf32_Shdr *shdr = &shdr_table[j];
                if (shdr->sh_type == SHT_SYMTAB)
                {
                    Elf32_Sym *symtab = (Elf32_Sym *)((char *)files[i]->map_start + shdr->sh_offset);
                    int sym_count = shdr->sh_size / sizeof(Elf32_Sym);
                    Elf32_Shdr *strtab_hdr = &shdr_table[shdr->sh_link];
                    const char *strtab = (const char *)files[i]->map_start + strtab_hdr->sh_offset;

                    for (int j = 0; j < sym_count; j++)
                    {
                        Elf32_Sym *sym = &symtab[j];
                        const char *name = strtab + sym->st_name;
                        sprintf(buff, "%d", sym->st_shndx);
                        const char *sec_name;
                        for (int k = 0; k < header->e_shnum; k++)
                        {
                            Elf32_Shdr *test_shdr = &shdr_table[k];
                            if (k == sym->st_shndx)
                            {
                                sec_name = sh_strtab + test_shdr->sh_name;
                            }
                        }
                        printf(print_sym_format, j, sym->st_value, sym->st_shndx < 1000 ? buff : "ABS", sec_name, (name[0]) ? name : sec_name);
                    }
                }
            }
        }
    }
}

sym_simple *get_syms(int file_index)
{
    if (files[file_index]->mapped)
    {

        //printf("File ELF - %s\n", files[file_index]->name);
        Elf32_Ehdr *header = (Elf32_Ehdr *)(files[file_index]->map_start);
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)(((char *)(files[file_index]->map_start)) + (header)->e_shoff);

        Elf32_Shdr *sh_strtab_hdr = &shdr_table[header->e_shstrndx];
        const char *sh_strtab = (const char *)files[file_index]->map_start + sh_strtab_hdr->sh_offset;
        for (int j = 0; j < header->e_shnum; j++)
        {
            char buff[10];
            Elf32_Shdr *shdr = &shdr_table[j];
            if (shdr->sh_type == SHT_SYMTAB)
            {
                Elf32_Sym *symtab = (Elf32_Sym *)((char *)files[file_index]->map_start + shdr->sh_offset);
                int sym_count = shdr->sh_size / sizeof(Elf32_Sym);

                sym_simple *to_ret = malloc(sizeof(sym_simple));
                to_ret->next = NULL;
                sym_simple *curr = to_ret;

                Elf32_Shdr *strtab_hdr = &shdr_table[shdr->sh_link];
                const char *strtab = (const char *)files[file_index]->map_start + strtab_hdr->sh_offset;
                for (int j = 0; j < sym_count; j++)
                {
                    Elf32_Sym *sym = &symtab[j];
                    const char *name = strtab + sym->st_name;
                    if (name != NULL && name[0])
                    {
                        curr->name = name;
                        curr->section_index = sym->st_shndx;
                        curr->next = malloc(sizeof(sym_simple));
                        curr = curr->next;
                        curr->next = NULL;
                        curr->section_index = 0;
                    }
                }

                return to_ret->next;
            }
        }
    }
    return NULL;
}

void chk_files_for_mrg()
{
    int indexes[FILES_COUNT];
    int no_valid = 0;
    int curr_index = 0;
    for (int i = 0; i < FILES_COUNT; i++)
    {
        if (files[i]->mapped)
        {
            indexes[curr_index] = i;
            curr_index++;
            no_valid++;
        }
    }
    if (no_valid < 2)
    {
        printf("ERROR : (%d/2) files open\n", no_valid);
    }
    else
    {
        for (int fst = 0; fst < no_valid; fst++)
        {
            sym_simple *sym_fst = get_syms(indexes[fst]);
            for (int snd = 0; snd < no_valid; snd++)
            {
                sym_simple *curr_fst = sym_fst;
                if (snd != fst)
                {
                    
                    while (curr_fst != NULL && curr_fst->name != NULL)
                    {
                        sym_simple *sym_snd = get_syms(indexes[snd]);
                        char match = 0;
                        while (sym_snd != NULL && sym_snd->name != NULL)
                        {
                            if (strcmp(curr_fst->name, sym_snd->name) == 0)
                            {

                                match = 1;
                                if (curr_fst->section_index == 0 || curr_fst->section_index > 1000)
                                {
                                    if (sym_snd->section_index == 0 || sym_snd->section_index > 1000)
                                    {
                                        printf("Symbol %s undefined\n", curr_fst->name);
                                    }
                                }
                                if (curr_fst->section_index > 0 && curr_fst->section_index < 1000 && sym_snd->section_index > 0 && sym_snd->section_index < 1000)
                                {
                                    printf("Symbol %s multibly defined\n", curr_fst->name);
                                }
                            }
                            sym_snd = sym_snd->next;
                        }

                        if (match == 0)
                        {
                            if (curr_fst->section_index == 0 || curr_fst->section_index > 1000)
                            {
                                printf("Symbol %s undefined 2\n", curr_fst->name);
                            }
                        }
                        curr_fst = curr_fst->next;
                    }
                }
            }
        }
    }
}

void mrg_elf_files()
{
    printf("NYE : mrg_elf_files\n");
}

menu_item *menu[7];

void free_menu()
{
    for (int i = 0; i <= 6; i++)
    {
        free(menu[i]);
    }
    for (int i = 0; i < FILES_COUNT; i++)
    {
        if (files[i]->mapped == 1)
        {
            munmap(files[i]->map_start, files[i]->size);
            free(files[i]->name);
            free(files[i]);
        }
    }
}

void print_menu()
{
    for (int i = 0; i <= 6; i++)
    {
        printf("%d-%s\n", i, menu[i]->text);
    }
}

int check_zero(char *input)
{
    while (1)
    {
        if (*input == '\0' || *input == '\n')
            return 1;
        else if (*input != '0')
            return 0;
        input++;
    }
}

void quit()
{
    printf("quitting...\n");
    free_menu();
    exit(0);
}

char *text_arr[] = {"Toggle Debug Mode", "Examine ELF File", "Print Section Names", "Print Symbols", "Check Files for Merge", "Merge ELf Files", "Quit"};
void *func_arr[] = {tgl_debug_mode, exmn_elf_file, prnt_sectns_names, prnt_sym, chk_files_for_mrg, mrg_elf_files, quit};

void make_menu()
{
    for (int i = 0; i <= 6; i++)
    {
        menu[i] = malloc(sizeof(menu_item));
        menu[i]->text = text_arr[i];
        menu[i]->func = func_arr[i];
    }

    for (int i = 0; i <= FILES_COUNT; i++)
    {
        files[i] = malloc(sizeof(mapped_file));
        files[i]->mapped = 0;
    }
}

int main(int argc, char *argv[])
{
    int selected = -1;
    char *input;
    int errReading = 0;
    make_menu();

    while (1)
    {
        input = malloc(100);
        errReading = 0;
        print_menu();
        fgets(input, 100, stdin);
        selected = atoi(input);
        if (selected == 0)
        {
            if (check_zero(input) == 0)
            {
                errReading = 1;
                printf("ERROR : error reading number from %s\n", input);
            }
        }
        free(input);
        if (selected > 6 || selected < 0)
        {
            printf("ERROR : selected option %d is out of range\n", selected);
        }
        else if (errReading == 0)
        {
            menu[selected]->func();
        }
    }
}
