/** Guard statement to avoid multiple declaration */
#ifndef AKA_SRC__HOME_HOANGANH_HA_SIMPLE_C_MAIN_C
#define AKA_SRC__HOME_HOANGANH_HA_SIMPLE_C_MAIN_C
extern int AKA_mark();
extern int AKA_fCall;

/** Instrumented function sum(int,int) */
int sum(int x, int y) /* << Aka begin of function int sum(int x, int y) >> */
{AKA_mark()/*Calling: ./simple-c/main.c/sum(int,int)*/;AKA_fCall++;AKA_mark()/*lis===1###sois===22###eois===43###lif===0###soif===22###eoif===43###function===./simple-c/main.c/sum(int,int)*/;
    AKA_mark()/*lis===2###sois===28###eois===41###lif===1###soif===28###eoif===41###ins===true###function===./simple-c/main.c/sum(int,int)*/;return x + y;
}

/** Instrumented function uut(int,int) */
void uut(int a, int b) /* << Aka begin of function void uut(int a, int b) >> */
{AKA_mark()/*Calling: ./simple-c/main.c/uut(int,int)*/;AKA_fCall++;AKA_mark()/*lis===5###sois===68###eois===242###lif===0###soif===23###eoif===197###function===./simple-c/main.c/uut(int,int)*/;
    AKA_mark()/*lis===6###sois===74###eois===97###lif===1###soif===29###eoif===52###ins===true###function===./simple-c/main.c/uut(int,int)*/;int result = sum(a, b);
    if (AKA_mark()/*lis===7###sois===106###eois===118###lif===2###soif===61###eoif===73###ifc===true###function===./simple-c/main.c/uut(int,int)*/ && (AKA_mark()/*lis===7###sois===106###eois===118###lif===2###soif===61###eoif===73###isc===true###function===./simple-c/main.c/uut(int,int)*/ && (result == 42))) {AKA_mark()/*lis===7###sois===120###eois===140###lif===2###soif===75###eoif===95###function===./simple-c/main.c/uut(int,int)*/;
        AKA_mark()/*lis===8###sois===130###eois===134###lif===3###soif===85###eoif===89###ins===true###function===./simple-c/main.c/uut(int,int)*/;a++;
    } else {AKA_mark()/*lis===9###sois===146###eois===166###lif===4###soif===101###eoif===121###function===./simple-c/main.c/uut(int,int)*/;
        AKA_mark()/*lis===10###sois===156###eois===160###lif===5###soif===111###eoif===115###ins===true###function===./simple-c/main.c/uut(int,int)*/;b++;
    }

    AKA_mark()/*lis===13###sois===172###eois===196###lif===8###soif===127###eoif===151###ins===true###function===./simple-c/main.c/uut(int,int)*/;int result2 = sum(a, b);
    if (AKA_mark()/*lis===14###sois===205###eois===217###lif===9###soif===160###eoif===172###ifc===true###function===./simple-c/main.c/uut(int,int)*/ && (AKA_mark()/*lis===14###sois===205###eois===217###lif===9###soif===160###eoif===172###isc===true###function===./simple-c/main.c/uut(int,int)*/ && (result2 == 0))) {AKA_mark()/*lis===14###sois===219###eois===239###lif===9###soif===174###eoif===194###function===./simple-c/main.c/uut(int,int)*/;
        AKA_mark()/*lis===15###sois===229###eois===233###lif===10###soif===184###eoif===188###ins===true###function===./simple-c/main.c/uut(int,int)*/;a--;
    }
else {
AKA_mark()/*lis===-14-###sois===-205-###eois===-20512-###lif===-9-###soif===-###eoif===-172-###ins===true###function===./simple-c/main.c/uut(int,int)*/;
} 
}

/** Instrumented function main() */
int AKA_MAIN() /* << Aka begin of function int main() >> */
{AKA_mark()/*Calling: ./simple-c/main.c/main()*/;AKA_fCall++;AKA_mark()/*lis===19###sois===255###eois===289###lif===0###soif===11###eoif===45###function===./simple-c/main.c/main()*/;
    AKA_mark()/*lis===20###sois===261###eois===273###lif===1###soif===17###eoif===29###ins===true###function===./simple-c/main.c/main()*/;uut(10, 20);
    AKA_mark()/*lis===21###sois===278###eois===287###lif===2###soif===34###eoif===43###ins===true###function===./simple-c/main.c/main()*/;return 0;
}

#endif

