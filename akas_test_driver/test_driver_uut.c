#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "akas_source/main.c"

void aka_sim_writer_u32(uint32_t raw) {
    // log raw 4 bytes
}

void aka_sim_writer_u64(uint64_t raw) {
    // log raw 8 bytes
}

int main(void)
{
    char text[] = "Hello";
    MyStruct s = {10, 3.14f, 'A'};
    int numbers[] = {1, 2, 3, 4};

    int akas_return_uut = uut(5, 2.5f, text, &s, numbers, 4);

    aka_sim_writer_u32(akas_return_uut);
    aka_sim_writer_u32(s.a);
    return 0;
}
