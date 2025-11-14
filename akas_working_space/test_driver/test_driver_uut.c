#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "akas_source/main.c"  
#include "stub.h"


int AKA_mark() {return 1;}

void AKAS_assert_u32(uint32_t actual, uint32_t expected) {}

void AKAS_assert_u64(uint64_t actual, uint64_t expected) {}

int AKA_fCall = 0;



int main()
{
    //////////////// TEST SCRIPT //////////////////

    // Test case name: uut_int_manual_0
	


int v;


int AKA_EXPECTED_OUTPUT=0;

/* RootDataNode STATIC */
/* NormalNumberDataNode v */
/* NormalNumberDataNode RETURN */


	AKA_mark()/*<<PRE-CALLING>> Test uut_int_manual_0*/;int AKA_ACTUAL_OUTPUT = uut(v);
	AKA_fCall++;AKA_mark()/*Return from: ./stub/teststub.c/uut(int)*/;
	AKAS_assert_u32(AKA_ACTUAL_OUTPUT, AKA_EXPECTED_OUTPUT);





    ///////////////////// END /////////////////////
    return 0;
}

