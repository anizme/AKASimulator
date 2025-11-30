
firmware.elf:	file format elf32-littlearm

Disassembly of section .text:

08000118 <Reset_Handler>:
 8000118: df           	<unknown>
 8000119: f8 2c        	cmp	r4, #248
 800011b: d0 0b        	lsrs	r0, r2, #15
 800011d: 48 0c        	lsrs	r0, r1, #17
 800011f: 49 0c        	lsrs	r1, r1, #17
 8000121: 4a 00        	lsls	r2, r1, #1
 8000123: 23 91        	str	r1, [sp, #140]

08000124 <copy_data>:
 8000124: 91 42        	cmp	r1, r2
 8000126: 03 da        	bge	0x8000130 <copy_done>   @ imm = #6
 8000128: c4 58        	ldr	r4, [r0, r3]
 800012a: cc 50        	str	r4, [r1, r3]
 800012c: 1b 1d        	adds	r3, r3, #4
 800012e: f9 e7        	b	0x8000124 <copy_data>   @ imm = #-14

08000130 <copy_done>:
 8000130: 09 48        	ldr	r0, [pc, #36]           @ 0x8000158 <$d.2+0x10>
 8000132: 0a 49        	ldr	r1, [pc, #40]           @ 0x800015c <$d.2+0x14>
 8000134: 00 22        	movs	r2, #0

08000136 <clear_bss>:
 8000136: 88 42        	cmp	r0, r1
 8000138: 02 da        	bge	0x8000140 <clear_done>  @ imm = #4
 800013a: 40           	<unknown>
 800013b: f8 04        	lsls	r0, r7, #19
 800013d: 2b           	<unknown>
 800013e: fa e7        	b	0x8000136 <clear_bss>   @ imm = #-12

08000140 <clear_done>:
 8000140: 00 f0 7d f8  	bl	0x800023e <main>        @ imm = #250
 8000144: fe e7        	b	0x8000144 <clear_done+0x4> @ imm = #-4
 8000146: 00 00        	movs	r0, r0

08000148 <$d.2>:
 8000148:	00 50 00 20	.word	0x20005000
 800014c:	7c 02 00 08	.word	0x0800027c
 8000150:	00 00 00 20	.word	0x20000000
 8000154:	00 00 00 20	.word	0x20000000
 8000158:	00 00 00 20	.word	0x20000000
 800015c:	08 00 00 20	.word	0x20000008

08000160 <WWDG_IRQHandler>:
 8000160: fe e7        	b	0x8000160 <WWDG_IRQHandler> @ imm = #-4
 8000162: d4 d4        	bmi	0x800010e <test_driver_uut.c+0x800010e> @ imm = #-88

08000164 <stubFunc>:
 8000164: 80 b5        	push	{r7, lr}
 8000166: 6f 46        	mov	r7, sp
 8000168: 82 b0        	sub	sp, #8
 800016a: 01 90        	str	r0, [sp, #4]
 800016c: 00 f0 59 f8  	bl	0x8000222 <AKA_mark>    @ imm = #178
 8000170: 40           	<unknown>
 8000171: f2 00        	lsls	r2, r6, #3
 8000173: 01 c2        	stm	r2!, {r0}
 8000175: f2 00        	lsls	r2, r6, #3
 8000177: 01 08        	lsrs	r1, r0, #32
 8000179: 68 01        	lsls	r0, r5, #5
 800017b: 30 08        	lsrs	r0, r6, #32
 800017d: 60 00        	lsls	r0, r4, #1
 800017f: f0 50        	str	r0, [r6, r3]
 8000181: f8 00        	lsls	r0, r7, #3
 8000183: f0 4e        	ldr	r6, [pc, #960]          @ 0x8000544 <_etext+0x2c8>
 8000185: f8 01        	lsls	r0, r7, #7
 8000187: 98 40        	lsls	r0, r3
 8000189: 00 02        	lsls	r0, r0, #8
 800018b: b0 80        	strh	r0, [r6, #4]
 800018d: bd 80        	strh	r5, [r7, #4]

0800018e <uut>:
 800018e: 80 b5        	push	{r7, lr}
 8000190: 6f 46        	mov	r7, sp
 8000192: 84 b0        	sub	sp, #16
 8000194: 02 90        	str	r0, [sp, #8]
 8000196: 00 f0 44 f8  	bl	0x8000222 <AKA_mark>    @ imm = #136
 800019a: 40           	<unknown>
 800019b: f2 00        	lsls	r2, r6, #3
 800019d: 01 c2        	stm	r2!, {r0}
 800019f: f2 00        	lsls	r2, r6, #3
 80001a1: 01 08        	lsrs	r1, r0, #32
 80001a3: 68 01        	lsls	r0, r5, #5
 80001a5: 30 08        	lsrs	r0, r6, #32
 80001a7: 60 00        	lsls	r0, r4, #1
 80001a9: f0 3b        	subs	r3, #240
 80001ab: f8 00        	lsls	r0, r7, #3
 80001ad: f0 39        	subs	r1, #240
 80001af: f8 02        	lsls	r0, r7, #11
 80001b1: 98           	<unknown>
 80001b2: ff f7 d7 ff  	bl	0x8000164 <stubFunc>    @ imm = #-82
 80001b6: 01 90        	str	r0, [sp, #4]
 80001b8: 00 f0 33 f8  	bl	0x8000222 <AKA_mark>    @ imm = #102
 80001bc: 78           	<unknown>
 80001bd: b1           	<unknown>
 80001be: ff e7        	b	0x80001c0 <uut+0x32>    @ imm = #-2
 80001c0: 00 f0 2f f8  	bl	0x8000222 <AKA_mark>    @ imm = #94
 80001c4: 58           	<unknown>
 80001c5: b1           	<unknown>
 80001c6: ff e7        	b	0x80001c8 <uut+0x3a>    @ imm = #-2
 80001c8: 01 98        	ldr	r0, [sp, #4]
 80001ca: 0a 28        	cmp	r0, #10
 80001cc: 07 d1        	bne	0x80001de <uut+0x50>    @ imm = #14
 80001ce: ff e7        	b	0x80001d0 <uut+0x42>    @ imm = #-2
 80001d0: 00 f0 27 f8  	bl	0x8000222 <AKA_mark>    @ imm = #78
 80001d4: 00 f0 25 f8  	bl	0x8000222 <AKA_mark>    @ imm = #74
 80001d8: 01 20        	movs	r0, #1
 80001da: 03 90        	str	r0, [sp, #12]
 80001dc: 06 e0        	b	0x80001ec <uut+0x5e>    @ imm = #12
 80001de: 00 f0 20 f8  	bl	0x8000222 <AKA_mark>    @ imm = #64
 80001e2: 00 f0 1e f8  	bl	0x8000222 <AKA_mark>    @ imm = #60
 80001e6: 00 20        	movs	r0, #0
 80001e8: 03 90        	str	r0, [sp, #12]
 80001ea: ff e7        	b	0x80001ec <uut+0x5e>    @ imm = #-2
 80001ec: 03 98        	ldr	r0, [sp, #12]
 80001ee: 04 b0        	add	sp, #16
 80001f0: 80 bd        	pop	{r7, pc}

080001f2 <AKA_stub_stubFunc>:
 80001f2: 84 b0        	sub	sp, #16
 80001f4: 02 90        	str	r0, [sp, #8]
 80001f6: 40           	<unknown>
 80001f7: f2 04        	lsls	r2, r6, #19
 80001f9: 00           	<unknown>
 80001fa: c2           	<unknown>
 80001fb: f2 00        	lsls	r2, r6, #3
 80001fd: 00 01        	lsls	r0, r0, #4
 80001ff: 68 01        	lsls	r0, r5, #5
 8000201: 31 01        	lsls	r1, r6, #4
 8000203: 60 00        	lsls	r0, r4, #1
 8000205: 68 01        	lsls	r0, r5, #5
 8000207: 28 05        	lsls	r0, r5, #20
 8000209: d1           	<unknown>
 800020a: ff e7        	b	0x800020c <AKA_stub_stubFunc+0x1a> @ imm = #-2
 800020c: 0a 20        	movs	r0, #10
 800020e: 00 90        	str	r0, [sp]
 8000210: 00 98        	ldr	r0, [sp]
 8000212: 03 90        	str	r0, [sp, #12]
 8000214: 02 e0        	b	0x800021c <AKA_stub_stubFunc+0x2a> @ imm = #4
 8000216: 00 20        	movs	r0, #0
 8000218: 03 90        	str	r0, [sp, #12]
 800021a: ff e7        	b	0x800021c <AKA_stub_stubFunc+0x2a> @ imm = #-2
 800021c: 03 98        	ldr	r0, [sp, #12]
 800021e: 04 b0        	add	sp, #16
 8000220: 70 47        	bx	lr

08000222 <AKA_mark>:
 8000222: 01 20        	movs	r0, #1
 8000224: 70 47        	bx	lr

08000226 <AKAS_assert_u32>:
 8000226: 82 b0        	sub	sp, #8
 8000228: 01 90        	str	r0, [sp, #4]
 800022a: 00 91        	str	r1, [sp]
 800022c: 02 b0        	add	sp, #8
 800022e: 70 47        	bx	lr

08000230 <AKAS_assert_u64>:
 8000230: 84 b0        	sub	sp, #16
 8000232: 03 91        	str	r1, [sp, #12]
 8000234: 02 90        	str	r0, [sp, #8]
 8000236: 01 93        	str	r3, [sp, #4]
 8000238: 00 92        	str	r2, [sp]
 800023a: 04 b0        	add	sp, #16
 800023c: 70 47        	bx	lr

0800023e <main>:
 800023e: 80 b5        	push	{r7, lr}
 8000240: 6f 46        	mov	r7, sp
 8000242: 86 b0        	sub	sp, #24
 8000244: 00 20        	movs	r0, #0
 8000246: 01 90        	str	r0, [sp, #4]
 8000248: 05 90        	str	r0, [sp, #20]
 800024a: ff f7 ea ff  	bl	0x8000222 <AKA_mark>    @ imm = #-44
 800024e: 5a 20        	movs	r0, #90
 8000250: 04 90        	str	r0, [sp, #16]
 8000252: ff f7 e6 ff  	bl	0x8000222 <AKA_mark>    @ imm = #-52
 8000256: 04 98        	ldr	r0, [sp, #16]
 8000258: ff f7 99 ff  	bl	0x800018e <uut>         @ imm = #-206
 800025c: 02 90        	str	r0, [sp, #8]
 800025e: 40           	<unknown>
 800025f: f2 00        	lsls	r2, r6, #3
 8000261: 01 c2        	stm	r2!, {r0}
 8000263: f2 00        	lsls	r2, r6, #3
 8000265: 01 08        	lsrs	r1, r0, #32
 8000267: 68 01        	lsls	r0, r5, #5
 8000269: 30 08        	lsrs	r0, r6, #32
 800026b: 60           	<unknown>
 800026c: ff f7 d9 ff  	bl	0x8000222 <AKA_mark>    @ imm = #-78
 8000270: ff f7 d7 ff  	bl	0x8000222 <AKA_mark>    @ imm = #-82
 8000274: 01 98        	ldr	r0, [sp, #4]
 8000276: 06 b0        	add	sp, #24
 8000278: 80 bd        	pop	{r7, pc}
 800027a: d4 d4        	bmi	0x8000226 <AKAS_assert_u32> @ imm = #-88
