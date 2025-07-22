#define RCC_APB2ENR (*(volatile unsigned int*)0x40021018)
#define GPIOC_CRH   (*(volatile unsigned int*)0x40011004)
#define GPIOC_ODR   (*(volatile unsigned int*)0x4001100C)

void delay(volatile int time) {
    while (time--);
}

int main(void) {
    RCC_APB2ENR |= (1 << 4);      // Enable GPIOC clock
    GPIOC_CRH &= ~(0xF << 20);    // Clear CNF13/MODE13
    GPIOC_CRH |=  (1 << 20);      // MODE13 = 01 (output 10MHz)
    
    while (1) {
        GPIOC_ODR ^= (1 << 13);   // Toggle PC13
        delay(100000);
    }
}
