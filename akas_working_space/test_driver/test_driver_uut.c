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

    // Test case name: uut_int_int_manual_0
	


int a=8;


int b=9;

/* RootDataNode STATIC */
/* NormalNumberDataNode a */
/* NormalNumberDataNode b */


	AKA_mark()/*<<PRE-CALLING>> Test uut_int_int_manual_0*/;uut(a,b);
	AKA_fCall++;AKA_mark()/*Return from: ./simple-c/main.c/uut(int,int)*/;
	/* error assertion */





    ///////////////////// END /////////////////////
    return 0;
}


