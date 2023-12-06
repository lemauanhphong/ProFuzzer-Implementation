#include <stdio.h>
#include <string.h>

int main() {
    // FILE *debug = fopen("input", "a");;
    // int n;
    // scanf("%d", &n);
    // printf("%d\n", n);
    // if (n == 2) printf("asd");
    // fprintf(debug, "%d\n", n);

    char buffer[100];
    read(0, buffer, 8);

    int n;
    memcpy(&n, buffer, 2);
    if (n == 2) printf("hehe");

    memcpy(&n, buffer + 2, 2);
    for (int i = 0; i < n; ++i) printf("asd");

    memcpy(&n, buffer + 4, 2);
    if (n == 1) printf("1\n");
    if (n == 123) printf("123\n");
    if (n == 45) printf("45\n");

    memcpy(&n, buffer + 6, 2);

    
    

    return 0;
}