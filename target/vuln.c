#include <stdio.h>

int main() {
    FILE *debug = fopen("input", "a");;
    int n;
    scanf("%d", &n);
    fprintf(debug, "%d\n", n);
    for (int i = 0; i < n; ++i) printf("hehe");
    return 0;
}