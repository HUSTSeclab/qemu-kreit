#include "func.h"
#include "ring0.h"

#define SIZE 100

void test() {
    int *p = (int *)_malloc(sizeof(int) * SIZE);

    for (int i = 0; i < SIZE * 2; i++) {
        p[i] = i;
    }
}

int main() {
    ring0(test);
    return 0;
}
