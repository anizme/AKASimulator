/** Guard statement to avoid multiple declaration */
#ifndef AKA_SRC__HOME_ANIZME_DOCUMENTS_AKA_TESTSOURCES_SIMULATION_STUB_TESTSTUB_C
#define AKA_SRC__HOME_ANIZME_DOCUMENTS_AKA_TESTSOURCES_SIMULATION_STUB_TESTSTUB_C
extern int AKA_mark();
extern int AKA_fCall;

#include <stdint.h>

// Hàm STUB giả lập giá trị trả về
/** Instrumented function stubFunc(int) */
int stubFunc(int x)
/* << Aka begin of function int stubFunc(int x) >> */
{AKA_mark()/*Calling: ./stub/teststub.c/stubFunc(int)*/;AKA_fCall++;AKA_mark()/*lis===5###sois===76###eois===98###lif===1###soif===20###eoif===42###function===./stub/teststub.c/stubFunc(int)*/;
    AKA_mark()/*lis===6###sois===82###eois===95###lif===2###soif===26###eoif===39###ins===true###function===./stub/teststub.c/stubFunc(int)*/;return x * 2; 
}


// ====== UUT (Unit Under Test) ======
/** Instrumented function uut(int) */
int uut(int v)
/* << Aka begin of function int uut(int v) >> */
{AKA_mark()/*Calling: ./stub/teststub.c/uut(int)*/;AKA_fCall++;AKA_mark()/*lis===12###sois===155###eois===201###lif===1###soif===15###eoif===61###function===./stub/teststub.c/uut(int)*/;
    AKA_mark()/*lis===13###sois===161###eois===181###lif===2###soif===21###eoif===41###ins===true###function===./stub/teststub.c/uut(int)*/;int t = stubFunc(v);
    AKA_mark()/*lis===14###sois===186###eois===199###lif===3###soif===46###eoif===59###ins===true###function===./stub/teststub.c/uut(int)*/;return t + 1;
}

#endif
