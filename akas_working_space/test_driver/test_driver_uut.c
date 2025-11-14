#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "akas_source/main.c"  
// #include "stub.h"


int AKA_mark() {return 1;}

void AKAS_assert_u32(uint32_t actual, uint32_t expected) {}

void AKAS_assert_u64(uint64_t actual, uint64_t expected) {}

int AKA_fCall = 0;


int main(void) {
    gpio_init();

    // Gọi từng hàm một để test lỗi
    // cause_divide_by_zero();          // lỗi chia 0
    cause_null_pointer_deref();   // lỗi con trỏ NULL
    // cause_stack_overflow();       // lỗi tràn stack
    // cause_function_pointer_crash(); // gọi vào địa chỉ rác

    set_led(1); // nếu tới đây, tức là không lỗi
    return 0;
}