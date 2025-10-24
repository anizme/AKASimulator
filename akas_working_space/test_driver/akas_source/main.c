/** Guard statement to avoid multiple declaration */
#ifndef AKA_SRC__HOME_ANIZME_DOCUMENTS_AKA_TESTSOURCES_SIMULATION_STRUCT_TEST_MAIN_C
#define AKA_SRC__HOME_ANIZME_DOCUMENTS_AKA_TESTSOURCES_SIMULATION_STRUCT_TEST_MAIN_C
extern int AKA_mark();
extern int AKA_fCall;

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Struct test
typedef struct
{
    int a;
    float b;
    char c;
} MyStruct;

// Unit Under Test (UUT)
/** Instrumented function uut(int,int,char*,MyStruct*,int*,size_t) */
int uut(int x, int y, char *msg, MyStruct *data, int *arr, size_t arr_len)
/* << Aka begin of function int uut(int x, int y, char *msg, MyStruct *data, int *arr, size_t arr_len) >> */
{
    AKA_mark() /*Calling: ./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
    AKA_fCall++;
    AKA_mark() /*lis===15###sois===257###eois===515###lif===1###soif===76###eoif===334###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
    AKA_mark() /*lis===16###sois===264###eois===295###lif===2###soif===83###eoif===114###ins===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
    int sum = x + (int)y + data->a;
    int AKA_BLOCK_LOOP_301 = 0;
    AKA_mark() /*lis===17###sois===306###eois===319###lif===3###soif===125###eoif===138###ins===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
    for (size_t i = 0; AKA_mark() /*lis===17###sois===320###eois===331###lif===3###soif===139###eoif===150###ifc===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/ && (AKA_mark() /*lis===17###sois===320###eois===331###lif===3###soif===139###eoif===150###isc===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/ && (i < arr_len)); ({AKA_mark()/*lis===17###sois===333###eois===336###lif===3###soif===152###eoif===155###ins===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;i++; }))
    {
        AKA_BLOCK_LOOP_301++;
        if (AKA_BLOCK_LOOP_301 > 1000)
        {
            // break;
        }
        AKA_mark() /*lis===18###sois===343###eois===375###lif===4###soif===162###eoif===194###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
        AKA_mark() /*lis===19###sois===354###eois===368###lif===5###soif===173###eoif===187###ins===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
        sum += arr[i];
    }
    if (AKA_mark() /*lis===21###sois===385###eois===388###lif===7###soif===204###eoif===207###ifc===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/ && (AKA_mark() /*lis===21###sois===385###eois===388###lif===7###soif===204###eoif===207###isc===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/ && (msg)))
    {
        AKA_mark() /*lis===22###sois===395###eois===469###lif===8###soif===214###eoif===288###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
        // Giả sử làm gì đó với msg
        AKA_mark() /*lis===24###sois===443###eois===462###lif===10###soif===262###eoif===281###ins===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
        sum += (int)msg[0];
    }
    else
    {
        AKA_mark() /*lis===-21-###sois===-385-###eois===-3853-###lif===-7-###soif===-###eoif===-207-###ins===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
    }
    AKA_mark() /*lis===26###sois===475###eois===495###lif===12###soif===294###eoif===314###ins===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
    sum += (int)data->c;
    AKA_mark() /*lis===27###sois===501###eois===512###lif===13###soif===320###eoif===331###ins===true###function===./struct_test/main.c/uut(int,int,char*,MyStruct*,int*,size_t)*/;
    return sum;
}
#endif
