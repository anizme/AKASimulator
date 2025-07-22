/* startup_stm32f103c8tx.s for STM32F103C8T6 */
/* Based on RM0008 Reference Manual, Section 9: Interrupts and Events */

.syntax unified
.cpu cortex-m3
.fpu softvfp
.thumb

/* Ký hiệu toàn cục */
.global g_vectors
.global Default_Handler
.global Reset_Handler

/* Ký hiệu từ linker script */
.extern _sdata
.extern _edata
.extern _sidata
.extern _sbss
.extern _ebss
.extern _estack
.extern main

/* Section bảng vector ngắt */
.section .isr_vector,"a",%progbits
.type g_vectors, %object
g_vectors:
    .word _estack               /* Stack pointer ban đầu */
    .word Reset_Handler         /* Vector reset */
    .word NMI_Handler           /* Non-Maskable Interrupt */
    .word HardFault_Handler     /* Hard Fault */
    .word MemManage_Handler     /* Memory Management */
    .word BusFault_Handler      /* Bus Fault */
    .word UsageFault_Handler    /* Usage Fault */
    .word 0                     /* Reserved */
    .word 0                     /* Reserved */
    .word 0                     /* Reserved */
    .word 0                     /* Reserved */
    .word SVCall_Handler        /* SVCall */
    .word DebugMon_Handler      /* Debug Monitor */
    .word 0                     /* Reserved */
    .word PendSV_Handler        /* PendSV */
    .word SysTick_Handler       /* SysTick */
    /* STM32F103C8T6-specific interrupts (from RM0008, Table 61) */
    .word WWDG_IRQHandler       /* Window Watchdog */
    .word PVD_IRQHandler        /* PVD through EXTI Line detection */
    .word TAMPER_IRQHandler     /* Tamper */
    .word RTC_IRQHandler        /* RTC */
    .word FLASH_IRQHandler      /* Flash */
    .word RCC_IRQHandler        /* RCC */
    .word EXTI0_IRQHandler      /* EXTI Line 0 */
    .word EXTI1_IRQHandler      /* EXTI Line 1 */
    .word EXTI2_IRQHandler      /* EXTI Line 2 */
    .word EXTI3_IRQHandler      /* EXTI Line 3 */
    .word EXTI4_IRQHandler      /* EXTI Line 4 */
    .word DMA1_Channel1_IRQHandler  /* DMA1 Channel 1 */
    .word DMA1_Channel2_IRQHandler  /* DMA1 Channel 2 */
    .word DMA1_Channel3_IRQHandler  /* DMA1 Channel 3 */
    .word DMA1_Channel4_IRQHandler  /* DMA1 Channel 4 */
    .word DMA1_Channel5_IRQHandler  /* DMA1 Channel 5 */
    .word DMA1_Channel6_IRQHandler  /* DMA1 Channel 6 */
    .word DMA1_Channel7_IRQHandler  /* DMA1 Channel 7 */
    .word ADC1_2_IRQHandler     /* ADC1 and ADC2 */
    .word USB_HP_CAN1_TX_IRQHandler /* USB High Priority or CAN1 TX */
    .word USB_LP_CAN1_RX0_IRQHandler /* USB Low Priority or CAN1 RX0 */
    .word CAN1_RX1_IRQHandler   /* CAN1 RX1 */
    .word CAN1_SCE_IRQHandler   /* CAN1 SCE */
    .word EXTI9_5_IRQHandler    /* EXTI Lines 5-9 */
    .word TIM1_BRK_IRQHandler   /* TIM1 Break */
    .word TIM1_UP_IRQHandler    /* TIM1 Update */
    .word TIM1_TRG_COM_IRQHandler /* TIM1 Trigger and Commutation */
    .word TIM1_CC_IRQHandler    /* TIM1 Capture Compare */
    .word TIM2_IRQHandler       /* TIM2 */
    .word TIM3_IRQHandler       /* TIM3 */
    .word TIM4_IRQHandler       /* TIM4 */
    .word I2C1_EV_IRQHandler    /* I2C1 Event */
    .word I2C1_ER_IRQHandler    /* I2C1 Error */
    .word I2C2_EV_IRQHandler    /* I2C2 Event */
    .word I2C2_ER_IRQHandler    /* I2C2 Error */
    .word SPI1_IRQHandler       /* SPI1 */
    .word SPI2_IRQHandler       /* SPI2 */
    .word USART1_IRQHandler     /* USART1 */
    .word USART2_IRQHandler     /* USART2 */
    .word USART3_IRQHandler     /* USART3 */
    .word EXTI15_10_IRQHandler  /* EXTI Lines 10-15 */
    .word RTC_Alarm_IRQHandler  /* RTC Alarm through EXTI Line */
    .word USBWakeUp_IRQHandler  /* USB Wakeup from suspend */
    .word 0                     /* Reserved */
    .word 0                     /* Reserved */
    .word 0                     /* Reserved */
    .word 0                     /* Reserved */
    .word 0                     /* Reserved */
    .word 0                     /* Reserved */
    .word 0                     /* Reserved */
    .size g_vectors, .-g_vectors

/* Reset Handler */
.section .text.Reset_Handler
.weak Reset_Handler
.type Reset_Handler, %function
Reset_Handler:
    /* Thiết lập stack pointer */
    ldr sp, =_estack

    /* Sao chép section .data từ Flash sang SRAM */
    ldr r0, =_sidata    /* Địa chỉ nguồn (Flash) */
    ldr r1, =_sdata     /* Địa chỉ đích (SRAM) */
    ldr r2, =_edata     /* Địa chỉ kết thúc .data */
    movs r3, #0         /* Bộ đếm */
copy_data:
    cmp r1, r2          /* Kiểm tra nếu đã sao chép hết */
    bge copy_done
    ldr r4, [r0, r3]    /* Đọc từ Flash */
    str r4, [r1, r3]    /* Ghi vào SRAM */
    adds r3, r3, #4     /* Tăng bộ đếm (4 byte) */
    b copy_data
copy_done:

    /* Xóa section .bss về 0 */
    ldr r0, =_sbss      /* Địa chỉ bắt đầu .bss */
    ldr r1, =_ebss      /* Địa chỉ kết thúc .bss */
    movs r2, #0         /* Giá trị 0 */
clear_bss:
    cmp r0, r1          /* Kiểm tra nếu đã xóa hết */
    bge clear_done
    str r2, [r0], #4    /* Ghi 0 và tăng con trỏ */
    b clear_bss
clear_done:

    /* Gọi hàm main */
    bl main

    /* Vòng lặp vô hạn nếu main trả về */
    b .
.size Reset_Handler, .-Reset_Handler

/* Default Handler cho các ngắt không được định nghĩa */
.section .text.Default_Handler,"ax",%progbits
Default_Handler:
    b .                 /* Vòng lặp vô hạn */
.size Default_Handler, .-Default_Handler

/* Định nghĩa weak alias cho các handler ngắt */
.macro def_irq_handler handler_name
.weak \handler_name
.set \handler_name, Default_Handler
.endm

def_irq_handler NMI_Handler
def_irq_handler HardFault_Handler
def_irq_handler MemManage_Handler
def_irq_handler BusFault_Handler
def_irq_handler UsageFault_Handler
def_irq_handler SVCall_Handler
def_irq_handler DebugMon_Handler
def_irq_handler PendSV_Handler
def_irq_handler SysTick_Handler
def_irq_handler WWDG_IRQHandler
def_irq_handler PVD_IRQHandler
def_irq_handler TAMPER_IRQHandler
def_irq_handler RTC_IRQHandler
def_irq_handler FLASH_IRQHandler
def_irq_handler RCC_IRQHandler
def_irq_handler EXTI0_IRQHandler
def_irq_handler EXTI1_IRQHandler
def_irq_handler EXTI2_IRQHandler
def_irq_handler EXTI3_IRQHandler
def_irq_handler EXTI4_IRQHandler
def_irq_handler DMA1_Channel1_IRQHandler
def_irq_handler DMA1_Channel2_IRQHandler
def_irq_handler DMA1_Channel3_IRQHandler
def_irq_handler DMA1_Channel4_IRQHandler
def_irq_handler DMA1_Channel5_IRQHandler
def_irq_handler DMA1_Channel6_IRQHandler
def_irq_handler DMA1_Channel7_IRQHandler
def_irq_handler ADC1_2_IRQHandler
def_irq_handler USB_HP_CAN1_TX_IRQHandler
def_irq_handler USB_LP_CAN1_RX0_IRQHandler
def_irq_handler CAN1_RX1_IRQHandler
def_irq_handler CAN1_SCE_IRQHandler
def_irq_handler EXTI9_5_IRQHandler
def_irq_handler TIM1_BRK_IRQHandler
def_irq_handler TIM1_UP_IRQHandler
def_irq_handler TIM1_TRG_COM_IRQHandler
def_irq_handler TIM1_CC_IRQHandler
def_irq_handler TIM2_IRQHandler
def_irq_handler TIM3_IRQHandler
def_irq_handler TIM4_IRQHandler
def_irq_handler I2C1_EV_IRQHandler
def_irq_handler I2C1_ER_IRQHandler
def_irq_handler I2C2_EV_IRQHandler
def_irq_handler I2C2_ER_IRQHandler
def_irq_handler SPI1_IRQHandler
def_irq_handler SPI2_IRQHandler
def_irq_handler USART1_IRQHandler
def_irq_handler USART2_IRQHandler
def_irq_handler USART3_IRQHandler
def_irq_handler EXTI15_10_IRQHandler
def_irq_handler RTC_Alarm_IRQHandler
def_irq_handler USBWakeUp_IRQHandler

