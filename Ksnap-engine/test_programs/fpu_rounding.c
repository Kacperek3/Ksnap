// Build with: make test_programs

#include <fenv.h>
#include <stdio.h>
#include <unistd.h>

static char sse_mode(void) {
    volatile double one = 1.0, minus_one = -1.0, three = 3.0;
    double up = one / three;
    double down = -(minus_one / three);
    return up > down ? 'U' : 'N';
}

static char x87_mode(void) {
    volatile long double one = 1.0L, minus_one = -1.0L, three = 3.0L;
    long double up = one / three;
    long double down = -(minus_one / three);
    return up > down ? 'U' : 'N';
}

int main(void) {
    printf("fpu_rounding pid: %d\n", getpid());

    if (fesetround(FE_UPWARD) != 0) {
        printf("cannot set the rounding mode\n");
        return 1;
    }

    for (int i = 0; i < 100; i++) {
        printf("%d sse=%c x87=%c\n", i, sse_mode(), x87_mode());
        fflush(stdout);
        sleep(1);
    }

    return 0;
}
