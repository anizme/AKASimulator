#include <stdint.h>
#include <stdlib.h> // nếu môi trường có malloc/free
#include <stdint.h>

// Map thanh ghi ngoại vi
#define RCC_APB2ENR (*(volatile uint32_t *)0x40021018)
#define GPIOC_CRH (*(volatile uint32_t *)0x40011004)
#define GPIOC_ODR (*(volatile uint32_t *)0x4001100C)

// Kiểm tra bit thứ pin có đang bị clear hay không (dạng active-low button)
int is_button_pressed(uint32_t gpio_idr, int pin)
{
    return !(gpio_idr & (1 << pin));
}

void gpio_init()
{
    RCC_APB2ENR |= (1 << 4);   // Bật clock GPIOC
    GPIOC_CRH &= ~(0xF << 20); // Clear CNF13/MODE13
    GPIOC_CRH |= (0x1 << 20);  // MODE13 = 01: output push-pull 10MHz
}

void set_led(int on)
{
    if (on)
        GPIOC_ODR &= ~(1 << 13); // LED on (PC13 = 0)
    else
        GPIOC_ODR |= (1 << 13); // LED off (PC13 = 1)
}

// 1. Truy cập con trỏ NULL
uint32_t cause_null_pointer_deref() {
    volatile uint32_t *ptr = NULL;
    return *ptr;
}

// 2. Truy cập địa chỉ không hợp lệ
void cause_invalid_address_access() {
    volatile uint32_t *ptr = (uint32_t *)0x12345678; // không mapped
    *ptr = 0xCAFEBABE;
}

// 3. Chia cho 0
void cause_divide_by_zero() {
    volatile int a = 10;
    volatile int b = 0;
    volatile int c = a / b;
    (void)c;
}

// 4. Stack overflow bằng đệ quy vô hạn
void cause_stack_overflow() {
    cause_stack_overflow();
}

// 5. Buffer overflow
void cause_buffer_overflow() {
    char buf[4];
    for (int i = 0; i < 6; ++i) {
        buf[i] = 'A';
    }
}

// 6. Gọi function pointer chưa khởi tạo
void cause_function_pointer_crash() {
    void (*func)() = (void (*)())0xDEADC0DE;
    func();
}

// 7. Sử dụng biến chưa khởi tạo (undefined behavior)
int cause_uninitialized_variable_usage() {
    int x;  // không khởi tạo
    if (x == 1234) {
        return 1;
    }
    return 0;
}

// 8. Free vùng không cấp phát (nếu hệ thống hỗ trợ malloc)
// void cause_invalid_free() {
//     int dummy = 42;
//     free(&dummy); // invalid free
// }

// 9. Truy cập ngoài mảng
void cause_array_out_of_bounds() {
    int arr[2] = {1, 2};
    arr[2] = 100;
}

// 10. Truy cập NULL function pointer
void cause_null_function_call() {
    void (*f)() = NULL;
    f();
}

///////////////////////////////////////////////////////
////////////////// TEST DRIVER ////////////////////////
///////////////////////////////////////////////////////

void write_custom(int value) {
}

// void write_custom(int value) {
// }

