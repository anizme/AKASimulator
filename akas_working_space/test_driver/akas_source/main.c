/** Guard statement to avoid multiple declaration */
#ifndef AKA_SRC__HOME_HOANGANH_HA_SIMPLE_C_MAIN_C
#define AKA_SRC__HOME_HOANGANH_HA_SIMPLE_C_MAIN_C
extern int AKA_mark();
extern int AKA_fCall;


/** Instrumented function sum(int,int) */
int sum(int x, int y) /* << Aka begin of function int sum(int x, int y) >> */
{AKA_mark()/*Calling: ./simple-c/main.c/sum(int,int)*/;AKA_fCall++;AKA_mark()/*lis===2###sois===23###eois===44###lif===0###soif===22###eoif===43###function===./simple-c/main.c/sum(int,int)*/;
    AKA_mark()/*lis===3###sois===29###eois===42###lif===1###soif===28###eoif===41###ins===true###function===./simple-c/main.c/sum(int,int)*/;return x + y;
}

/** Instrumented function stub_function(int,int) */
int stub_function(int x, int y) /* << Aka begin of function int stub_function(int x, int y) >> */
{AKA_mark()/*Calling: ./simple-c/main.c/stub_function(int,int)*/;AKA_fCall++;AKA_mark()/*lis===6###sois===78###eois===96###lif===0###soif===32###eoif===50###function===./simple-c/main.c/stub_function(int,int)*/;
    AKA_mark()/*lis===7###sois===84###eois===94###lif===1###soif===38###eoif===48###ins===true###function===./simple-c/main.c/stub_function(int,int)*/;return 42;
}

/** Instrumented function uut(int,int) */
void uut(int a, int b) /* << Aka begin of function void uut(int a, int b) >> */
{AKA_mark()/*Calling: ./simple-c/main.c/uut(int,int)*/;AKA_fCall++;AKA_mark()/*lis===10###sois===121###eois===221###lif===0###soif===23###eoif===123###function===./simple-c/main.c/uut(int,int)*/;
    AKA_mark()/*lis===11###sois===127###eois===150###lif===1###soif===29###eoif===52###ins===true###function===./simple-c/main.c/uut(int,int)*/;int result = sum(a, b);
    if (AKA_mark()/*lis===12###sois===159###eois===171###lif===2###soif===61###eoif===73###ifc===true###function===./simple-c/main.c/uut(int,int)*/ && (AKA_mark()/*lis===12###sois===159###eois===171###lif===2###soif===61###eoif===73###isc===true###function===./simple-c/main.c/uut(int,int)*/ && (result == 42))) {AKA_mark()/*lis===12###sois===173###eois===193###lif===2###soif===75###eoif===95###function===./simple-c/main.c/uut(int,int)*/;
        AKA_mark()/*lis===13###sois===183###eois===187###lif===3###soif===85###eoif===89###ins===true###function===./simple-c/main.c/uut(int,int)*/;a++;
    } else {AKA_mark()/*lis===14###sois===199###eois===219###lif===4###soif===101###eoif===121###function===./simple-c/main.c/uut(int,int)*/;
        AKA_mark()/*lis===15###sois===209###eois===213###lif===5###soif===111###eoif===115###ins===true###function===./simple-c/main.c/uut(int,int)*/;b++;
    }
}


#endif

