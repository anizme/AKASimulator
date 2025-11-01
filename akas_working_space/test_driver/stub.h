#pragma once

int AKA_fCall_sum = 0;
int AKA_fCall_product = 0;

int AKA_stub_sum(int x, int y) {
    ++AKA_fCall_sum;
    if (AKA_fCall_sum == 1) {
        return 42;
    } 
    if (AKA_fCall_sum == 2) {
        return 0;
    }
    return 0;
}

int AKA_stub_product(int x, int y) {
    ++AKA_fCall_product;
    if (AKA_fCall_product == 1) {
        return 10;
    }
    return 0;
}