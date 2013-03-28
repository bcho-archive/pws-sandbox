#include <stdlib.h>

int main()
{
    int *p, k, j;

    for (j = 1000;j > 0;j--) {
        p = malloc(sizeof(char) * 1024);
        for (k = 0;k < 1024;k++)
            p[k] = rand();
    }

    return 0;
}
