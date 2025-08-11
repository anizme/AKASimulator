#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "akas_source/main.c"  

void aka_sim_writer_u32(uint32_t actual, uint32_t expected)
{
}

void aka_sim_writer_u64(uint64_t actual, uint64_t expected)
{
}

// static buffers for input data
static char msg[2];
static MyStruct data[1];
static int arr[1];
static size_t arr_len;

static char EXPECTED_msg[2];
static MyStruct EXPECTED_data[1];
static int EXPECTED_arr[1];
static size_t EXPECTED_arr_len;

int main(void)
{
    int x = 1;
    int y = 2;

    msg[0] = 49;
    msg[1] = 0;

    data[0].a = 1;
    data[0].c = 99;

    arr[0] = 1;
    arr_len = 1;

    int AKA_EXPECTED_OUTPUT = 0;
    int AKA_ACTUAL_OUTPUT = uut(x, y, msg, data, arr, arr_len);

    aka_sim_writer_u32(AKA_ACTUAL_OUTPUT, AKA_EXPECTED_OUTPUT);

    int EXPECTED_x = 2;
    int EXPECTED_y = 3;

    aka_sim_writer_u32(x, EXPECTED_x);
    aka_sim_writer_u32(y, EXPECTED_y);

    EXPECTED_msg[0] = 50;
    EXPECTED_msg[1] = 0;

    EXPECTED_data[0].a = 2;
    EXPECTED_data[0].c = 97;

    aka_sim_writer_u32(data[0].a, EXPECTED_data[0].a);
    aka_sim_writer_u32(data[0].c, EXPECTED_data[0].c);

    EXPECTED_arr[0] = 2;

    aka_sim_writer_u32(arr[0], EXPECTED_arr[0]);

    EXPECTED_arr_len = 1;
    aka_sim_writer_u32(arr_len, EXPECTED_arr_len);

    return 0; 
}
