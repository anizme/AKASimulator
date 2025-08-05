// main.c
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

int main(void)
{
    gpio_init();
    int failed = 0;
    // Test case 1: button pressed at pin 0
    if (is_button_pressed(0xFFFFFFFE, 0) != 1)
        failed++;
    // Kết quả
    set_led(failed == 0); // Pass → LED sáng, Fail → LED tắt
    return 0;
}
