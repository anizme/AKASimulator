#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Struct test
typedef struct
{
    int a;
    float b;
    char c;
} MyStruct;

// Unit Under Test (UUT)
int uut(int x, int y, char *msg, MyStruct *data, int *arr, size_t arr_len)
{
    int sum = x + (int)y + data->a;
    for (size_t i = 0; i < arr_len; i++)
    {
        sum += arr[i];
    }
    if (msg)
    {
        // Giả sử làm gì đó với msg
        sum += (int)msg[0];
    }
    sum += (int)data->c;
    return sum;
}

///////////////////////////////////////////////////////
////////////////// TEST DRIVER ////////////////////////
///////////////////////////////////////////////////////

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

    int result = uut(5, 2.5f, text, &s, numbers, 4);

    aka_sim_writer_u32(result);
    aka_sim_writer_u32(s.a);
    return 0;
}
