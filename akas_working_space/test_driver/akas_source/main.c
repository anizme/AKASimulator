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