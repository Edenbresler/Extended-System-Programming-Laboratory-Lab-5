#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <elf.h>

// Iterator over program headers
int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *, int), int arg)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start;
    Elf32_Phdr *phdr = (Elf32_Phdr *)((char *)map_start + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; ++i)
    {
        func(&phdr[i], arg);
    }
}
// Function to be applied to each program header task0
void process_phdr(Elf32_Phdr *phdr, int index)
{
    printf("Program header number %d at address 0x%x\n", index, phdr->p_offset);
}
// Function to be applied to each program header task1
void info_phdr(Elf32_Phdr *phdr, int index) 
{
    const char *type_str;

    
    if (phdr->p_type == PT_NULL)
        type_str = "NULL";
    else if (phdr->p_type == PT_LOAD) //loadable segment,defines a range of memory to be loaded from the file.
        type_str = "LOAD";
    else if (phdr->p_type == PT_DYNAMIC)//request dynamic linking
        type_str = "DYNAMIC";
    else if (phdr->p_type == PT_INTERP) //Specifies the location and size of a null-terminated path name to invoke as an interpreter.
        type_str = "INTERP";
    else if (phdr->p_type == PT_NOTE)//Specifies information about the file, usually in the form of a note section
        type_str = "NOTE";
    else if (phdr->p_type == PT_SHLIB)//pecifies the location and size of the program header table itself
        type_str = "SHLIB";
    else if (phdr->p_type == PT_PHDR)
        type_str = "PHDR";
    else if (phdr->p_type == PT_TLS)//Specifies the location and size of the thread-local storage template.
        type_str = "TLS";
    else if (phdr->p_type == PT_GNU_STACK) //GNU extension specifying the permissions of the stack
        type_str = "STACK";
    else if (phdr->p_type == PT_GNU_RELRO) //GNU extension specifying the location and size of the read-only segment
        type_str = "RELRO";
    else
        type_str = "UNKNOWN";

    printf("%s 0x%x 0x%x 0x%x 0x%x 0x%x", type_str, phdr->p_offset, phdr->p_vaddr, phdr->p_paddr, phdr->p_filesz, phdr->p_memsz);
    int flags = phdr->p_flags;

    if (flags == PF_X)
    {
        printf("E ");
    }
    else if (flags == PF_W)
    {
        printf("W ");
    }
    else if (flags == PF_R)
    {
        printf("R ");
    }
    else if (flags == (PF_X | PF_W))
    {
        printf("EW ");
    }
    else if (flags == (PF_X | PF_R))
    {
        printf("ER ");
    }
    else if (flags == (PF_W | PF_R))
    {
        printf("WR ");
    }
    else if (flags == (PF_X | PF_W | PF_R))
    {
        printf("EWR ");
    }
    else
    {
        printf("Unknown ");
    }

    printf("0x%x\n", phdr->p_align); 

    // Print protection flags for mmap-task1b
    int prot_flags = 0;
    if (phdr->p_flags & PF_R)
        prot_flags |= PROT_READ;
    if (phdr->p_flags & PF_W)
        prot_flags |= PROT_WRITE;
    if (phdr->p_flags & PF_X)
        prot_flags |= PROT_EXEC;

    // Print mapping flags for mmap
    int map_flags = MAP_PRIVATE | MAP_FIXED;

    
    if (phdr->p_type == PT_LOAD && phdr->p_filesz > 0)
        map_flags |= MAP_ANONYMOUS;

    printf(" Protection Flags: 0x%x, Mapping Flags: 0x%x\n", prot_flags, map_flags);
}

void load_phdr(Elf32_Phdr *phdr, int fd)
{
    if (phdr->p_type == PT_LOAD)
    {
        // Calculate aligned virtual address and offset
        Elf32_Off offset = phdr->p_offset & 0xfffff000;
        Elf32_Addr *vaddr = (Elf32_Addr *)(phdr->p_vaddr & 0xfffff000);
        size_t padding = phdr->p_vaddr & 0xfff;
        int prot = 0;
        if (phdr->p_flags & PF_X) 
            prot |= PROT_EXEC;
        if (phdr->p_flags & PF_W)
            prot |= PROT_WRITE;
        if (phdr->p_flags & PF_R)
            prot |= PROT_READ;

        // Map the segment into memory
        void *map = mmap(vaddr, phdr->p_memsz + padding,prot, MAP_PRIVATE | MAP_FIXED, fd, offset);
        if (map == MAP_FAILED)
        {
            perror("Error mapping phdr");
            exit(1);
        }
        info_phdr(phdr, fd);
    }
}
int startup(int argc, char **argv, void (*start)());

int main(int argc, char *argv[])
{
    // Open the ELF file
    int fd = open(argv[1], O_RDONLY);
    if (fd == -1)
    {
        perror("Error opening file");
        return 1;
    }
    // Get the file size
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Map the file into memory
    Elf32_Ehdr *map_start = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED)
    {
        perror("Error mapping file");
        close(fd);
        return 1;
    }

    printf("Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align\n");
    // Apply the iterator function
    foreach_phdr(map_start, load_phdr, fd);
    //execute the loaded program
    startup(argc - 1, argv + 1, (void *)(map_start->e_entry));

    // Unmap the file from memory
    munmap(map_start, size);

    // Close the file
    close(fd);

    return 0;
}