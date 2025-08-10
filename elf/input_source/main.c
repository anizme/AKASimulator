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

///////////////////////////////////////////////////////
////////////////// TEST DRIVER ////////////////////////
///////////////////////////////////////////////////////

void write_custom(int value) {
}

// void write_custom(int value) {
// }

int main(void) {
    gpio_init();

    int res = is_button_pressed(GPIOC_ODR, 13);

    write_custom(res);
    set_led(1);
    return 0;
}
