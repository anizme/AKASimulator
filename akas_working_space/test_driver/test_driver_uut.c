#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "akas_source/main.c"  


void aka_sim_writer_u32(uint32_t actual, uint32_t expected) {}

void aka_sim_writer_u64(uint64_t actual, uint64_t expected) {}



int main()
{
    //////////////// TEST SCRIPT //////////////////

    // Test case name: uut_int_int_charmul_MyStructmul_intmul_size_t_manual_0
	


int x=1;


int y=2;
static char AKAS_NOMALLOC_msg[2];
char* msg = AKAS_NOMALLOC_msg;



static MyStruct AKAS_NOMALLOC_data[1];
MyStruct* data = AKAS_NOMALLOC_data;

static int AKAS_NOMALLOC_arr[1];
int* arr = AKAS_NOMALLOC_arr;





size_t arr_len=2;


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
data[0].a=1;
/* b : null value -> no code */
data[0].c=1;
/* PointerNumberDataNode arr */
/* NormalNumberDataNode arr[0] */
arr[0]=1;

/* NormalNumberDataNode arr_len */
/* NormalNumberDataNode RETURN */


	int AKA_ACTUAL_OUTPUT = uut(x,y,msg,data,arr,arr_len);
	aka_sim_writer_u32(AKA_ACTUAL_OUTPUT, AKA_EXPECTED_OUTPUT);


size_t EXPECTED_arr_len=2;

aka_sim_writer_u32(arr_len, EXPECTED_arr_len);




    ///////////////////// END /////////////////////
    return 0;
}

