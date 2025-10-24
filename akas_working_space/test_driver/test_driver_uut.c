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
static int AKAS_NOMALLOC_arr[1];
int* arr = AKAS_NOMALLOC_arr;





size_t arr_len=1;


int AKA_EXPECTED_OUTPUT=0;

/* RootDataNode STATIC */
/* NormalNumberDataNode x */
/* NormalNumberDataNode y */
/* PointerCharacterDataNode msg */
/* NormalCharacterDataNode msg[0] */
msg[0]=97;
/* NormalCharacterDataNode msg[1] */
msg[1]=0;

/* PointerStructureDataNode data */
/* PointerNumberDataNode arr */
/* NormalNumberDataNode arr[0] */
arr[0]=1;

/* NormalNumberDataNode arr_len */
/* NormalNumberDataNode RETURN */


	int AKA_ACTUAL_OUTPUT = uut(x,y,msg,data,arr,arr_len);
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



MyStruct* EXPECTED_data = ((void *)0);

static int AKAS_NOMALLOC_EXPECTED_arr[1];
int* EXPECTED_arr = AKAS_NOMALLOC_EXPECTED_arr;


/* NormalNumberDataNode arr[0] */
EXPECTED_arr[0]=2;



AKAS_assert_u32(arr[0], EXPECTED_arr[0]);

size_t EXPECTED_arr_len=2;

AKAS_assert_u32(arr_len, EXPECTED_arr_len);




    ///////////////////// END /////////////////////
    return 0;
}


