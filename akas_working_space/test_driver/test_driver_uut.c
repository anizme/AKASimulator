#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "./akas_source/main.c"
#include "stub.h"




int AKA_mark() {return 1;}

void AKAS_assert_u32(uint32_t actual, uint32_t expected) {}

void AKAS_assert_u64(uint64_t actual, uint64_t expected) {}

int AKA_fCall = 0;



int main()
{
    //////////////// TEST SCRIPT //////////////////

    // Test case name: uut_int_manual_0
		AKA_mark()/*BEGIN OF UUT_INT_MANUAL_0*/;
	


int v=90;


int AKA_EXPECTED_OUTPUT;

/* RootDataNode STATIC */
/* NormalNumberDataNode v */
/* NormalNumberDataNode RETURN */


	AKA_mark()/*<<PRE-CALLING>> Test uut_int_manual_0*/;int AKA_ACTUAL_OUTPUT = uut(v);
	AKA_fCall++;AKA_mark()/*Return from: ./simple-c/main.c/uut(int)*/;
	

	AKA_mark()/*END OF UUT_INT_MANUAL_0*/;




    ///////////////////// END /////////////////////
    return 0;
}


