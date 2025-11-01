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

/** Instrumented function product(int,int) */
int product(int x, int y) /* << Aka begin of function int product(int x, int y) >> */
{AKA_mark()/*Calling: ./simple-c/main.c/product(int,int)*/;AKA_fCall++;AKA_mark()/*lis===5###sois===71###eois===92###lif===0###soif===26###eoif===47###function===./simple-c/main.c/product(int,int)*/;
    AKA_mark()/*lis===6###sois===77###eois===90###lif===1###soif===32###eoif===45###ins===true###function===./simple-c/main.c/product(int,int)*/;return x * y;
}

/** Instrumented function uut(int,int) */
void uut(int a, int b) /* << Aka begin of function void uut(int a, int b) >> */
{AKA_mark()/*Calling: ./simple-c/main.c/uut(int,int)*/;AKA_fCall++;AKA_mark()/*lis===9###sois===117###eois===368###lif===0###soif===23###eoif===274###function===./simple-c/main.c/uut(int,int)*/;
    AKA_mark()/*lis===10###sois===123###eois===146###lif===1###soif===29###eoif===52###ins===true###function===./simple-c/main.c/uut(int,int)*/;int result = sum(a, b);
    if (AKA_mark()/*lis===11###sois===155###eois===167###lif===2###soif===61###eoif===73###ifc===true###function===./simple-c/main.c/uut(int,int)*/ && (AKA_mark()/*lis===11###sois===155###eois===167###lif===2###soif===61###eoif===73###isc===true###function===./simple-c/main.c/uut(int,int)*/ && (result == 42))) {AKA_mark()/*lis===11###sois===169###eois===189###lif===2###soif===75###eoif===95###function===./simple-c/main.c/uut(int,int)*/;
        AKA_mark()/*lis===12###sois===179###eois===183###lif===3###soif===85###eoif===89###ins===true###function===./simple-c/main.c/uut(int,int)*/;a++;
    } else {AKA_mark()/*lis===13###sois===195###eois===215###lif===4###soif===101###eoif===121###function===./simple-c/main.c/uut(int,int)*/;
        AKA_mark()/*lis===14###sois===205###eois===209###lif===5###soif===111###eoif===115###ins===true###function===./simple-c/main.c/uut(int,int)*/;b++;
    }

    AKA_mark()/*lis===17###sois===221###eois===245###lif===8###soif===127###eoif===151###ins===true###function===./simple-c/main.c/uut(int,int)*/;int result2 = sum(a, b);
    if (AKA_mark()/*lis===18###sois===254###eois===266###lif===9###soif===160###eoif===172###ifc===true###function===./simple-c/main.c/uut(int,int)*/ && (AKA_mark()/*lis===18###sois===254###eois===266###lif===9###soif===160###eoif===172###isc===true###function===./simple-c/main.c/uut(int,int)*/ && (result2 == 0))) {AKA_mark()/*lis===18###sois===268###eois===288###lif===9###soif===174###eoif===194###function===./simple-c/main.c/uut(int,int)*/;
        AKA_mark()/*lis===19###sois===278###eois===282###lif===10###soif===184###eoif===188###ins===true###function===./simple-c/main.c/uut(int,int)*/;a--;
    }
else {
AKA_mark()/*lis===-18-###sois===-254-###eois===-25412-###lif===-9-###soif===-###eoif===-172-###ins===true###function===./simple-c/main.c/uut(int,int)*/;
} 

    if (AKA_mark()/*lis===22###sois===299###eois===318###lif===13###soif===205###eoif===224###ifc===true###function===./simple-c/main.c/uut(int,int)*/ && (AKA_mark()/*lis===22###sois===299###eois===318###lif===13###soif===205###eoif===224###isc===true###function===./simple-c/main.c/uut(int,int)*/ && (product(a, b) == 10))) {AKA_mark()/*lis===22###sois===320###eois===340###lif===13###soif===226###eoif===246###function===./simple-c/main.c/uut(int,int)*/;
        AKA_mark()/*lis===23###sois===330###eois===334###lif===14###soif===236###eoif===240###ins===true###function===./simple-c/main.c/uut(int,int)*/;b--;
    } else {AKA_mark()/*lis===24###sois===346###eois===366###lif===15###soif===252###eoif===272###function===./simple-c/main.c/uut(int,int)*/;
        AKA_mark()/*lis===25###sois===356###eois===360###lif===16###soif===262###eoif===266###ins===true###function===./simple-c/main.c/uut(int,int)*/;b++;
    }
}

/** Instrumented function main() */
int AKA_MAIN() /* << Aka begin of function int main() >> */
{AKA_mark()/*Calling: ./simple-c/main.c/main()*/;AKA_fCall++;AKA_mark()/*lis===29###sois===381###eois===415###lif===0###soif===11###eoif===45###function===./simple-c/main.c/main()*/;
    AKA_mark()/*lis===30###sois===387###eois===399###lif===1###soif===17###eoif===29###ins===true###function===./simple-c/main.c/main()*/;uut(10, 20);
    AKA_mark()/*lis===31###sois===404###eois===413###lif===2###soif===34###eoif===43###ins===true###function===./simple-c/main.c/main()*/;return 0;
}

#endif

