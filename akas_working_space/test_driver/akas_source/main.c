/** Guard statement to avoid multiple declaration */
#ifndef AKA_SRC__HOME_HOANGANH_HA_SIMPLE_C_MAIN_C
#define AKA_SRC__HOME_HOANGANH_HA_SIMPLE_C_MAIN_C
extern int AKA_mark();
extern int AKA_fCall;

#include <stdint.h>

// Hàm STUB giả lập giá trị trả về
/** Instrumented function stubFunc(int) */
int stubFunc(int x)
/* << Aka begin of function int stubFunc(int x) >> */
{AKA_mark()/*Calling: ./simple-c/main.c/stubFunc(int)*/;AKA_fCall++;AKA_mark()/*lis===5###sois===76###eois===98###lif===1###soif===20###eoif===42###function===./simple-c/main.c/stubFunc(int)*/;
    AKA_mark()/*lis===6###sois===82###eois===95###lif===2###soif===26###eoif===39###ins===true###function===./simple-c/main.c/stubFunc(int)*/;return x * 2; 
}


// ====== UUT (Unit Under Test) ======
/** Instrumented function uut(int) */
int uut(int v)
/* << Aka begin of function int uut(int v) >> */
{AKA_mark()/*Calling: ./simple-c/main.c/uut(int)*/;AKA_fCall++;AKA_mark()/*lis===12###sois===155###eois===257###lif===1###soif===15###eoif===117###function===./simple-c/main.c/uut(int)*/;
    AKA_mark()/*lis===13###sois===161###eois===181###lif===2###soif===21###eoif===41###ins===true###function===./simple-c/main.c/uut(int)*/;int t = stubFunc(v);
    if (AKA_mark()/*lis===14###sois===190###eois===197###lif===3###soif===50###eoif===57###ifc===true###function===./simple-c/main.c/uut(int)*/ && (AKA_mark()/*lis===14###sois===190###eois===197###lif===3###soif===50###eoif===57###isc===true###function===./simple-c/main.c/uut(int)*/ && (t == 10))) {AKA_mark()/*lis===14###sois===199###eois===224###lif===3###soif===59###eoif===84###function===./simple-c/main.c/uut(int)*/;
        AKA_mark()/*lis===15###sois===209###eois===218###lif===4###soif===69###eoif===78###ins===true###function===./simple-c/main.c/uut(int)*/;return 1;
    } else {AKA_mark()/*lis===16###sois===230###eois===255###lif===5###soif===90###eoif===115###function===./simple-c/main.c/uut(int)*/;
        AKA_mark()/*lis===17###sois===240###eois===249###lif===6###soif===100###eoif===109###ins===true###function===./simple-c/main.c/uut(int)*/;return 0;
    }
}
#endif

