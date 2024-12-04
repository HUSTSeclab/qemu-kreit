#include "func.h"
#include "ring0.h"

void test() {
    int *p = (int *)_malloc(sizeof(int));
    _free(p);
    _free(p);
}

int main() {
    ring0(test);
    return 0;
}
