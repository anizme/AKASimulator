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

int main(void) {
    gpio_init();


    // uint32_t x = cause_null_pointer_deref();          // 1. Gây lỗi con trỏ NULL -> Unicorn crash, da bat err de log
    // cause_invalid_address_access();      // 2. Gây lỗi truy cập địa chỉ không hợp lệ -> Unicorn crash, da bat err de log
    // cause_divide_by_zero();              // 3. Gây lỗi chia cho 0 -> Unicorn khong crash, da xu ly bang cach decode phat hien instruction devision, da log
    // cause_stack_overflow();              // 4. Gây tràn stack -> Unicorn crash( Tran stack den muc truy cap vao invalid memory)
    // cause_buffer_overflow();             // 5. Ghi tràn stack -> Unicorn khong crash
    // cause_function_pointer_crash();      // 6. Gọi function pointer rác -> Unicorn crash, chua hook log
    // cause_uninitialized_variable_usage(); // 7. Dùng biến chưa khởi tạo -> Unicorn khong crash, thuc te chay tren chip cung nguy hiem thoi chu khong loi
    // // cause_invalid_free();             // 8. Gọi free với con trỏ không hợp lệ (bỏ qua nếu không có malloc)
    // cause_array_out_of_bounds();         // 9. Ghi ngoài mảng -> Unicorn crash, da hook
    cause_null_function_call();          // 10. Gọi con trỏ hàm NULL -> Unicorn khong crash

    int res = is_button_pressed(GPIOC_ODR, 13);
    write_custom(res);
    set_led(1);
    return 0;
}