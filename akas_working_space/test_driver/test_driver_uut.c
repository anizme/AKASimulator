#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "akas_source/main.c"  


int AKA_mark() {return 1;}

void AKAS_assert_u32(uint32_t actual, uint32_t expected) {}

void AKAS_assert_u64(uint64_t actual, uint64_t expected) {}

int AKA_fCall = 0;



int main()
{
    //////////////// TEST SCRIPT //////////////////

    // Test case name: uut_int_int_charmul_MyStructmul_intmul_size_t_manual_0
	


int x=1;


int y=1;
static char AKAS_NOMALLOC_msg[2];
char* msg = AKAS_NOMALLOC_msg;



MyStruct* data = ((void *)0);
int* arr = ((void *)0);




size_t arr_len=1;


int AKA_EXPECTED_OUTPUT=0;

/* RootDataNode STATIC */
/* NormalNumberDataNode x */
/* NormalNumberDataNode y */
/* PointerCharacterDataNode msg */
/* NormalCharacterDataNode msg[0] */
msg[0]=49;
/* NormalCharacterDataNode msg[1] */
msg[1]=0;

/* PointerStructureDataNode data */
/* PointerNumberDataNode arr */

/* NormalNumberDataNode arr_len */
/* NormalNumberDataNode RETURN */


	AKA_mark()/*<<PRE-CALLING>> Test uut_int_int_charmul_MyStructmul_intmul_size_t_manual_0*/;int AKA_ACTUAL_OUTPUT = uut(x,y,msg,data,arr,arr_len);
	AKA_fCall++;AKA_mark()/*Return from: ./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
	AKAS_assert_u32(AKA_ACTUAL_OUTPUT, AKA_EXPECTED_OUTPUT);


int EXPECTED_x=2;

AKAS_assert_u32(x, EXPECTED_x);

int EXPECTED_y=2;

AKAS_assert_u32(y, EXPECTED_y);static char AKAS_NOMALLOC_EXPECTED_msg[2];
char* EXPECTED_msg = AKAS_NOMALLOC_EXPECTED_msg;


/* NormalCharacterDataNode msg[0] */
EXPECTED_msg[0]=50;
/* NormalCharacterDataNode msg[1] */
EXPECTED_msg[1]=0;





size_t EXPECTED_arr_len=2;

AKAS_assert_u32(arr_len, EXPECTED_arr_len);




    ///////////////////// END /////////////////////
    return 0;
}


