// Build with: make test_programs

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

typedef double v4df __attribute__((vector_size(32)));

// 2^26 iterations, a few lines per second on a current CPU
#define REPORT_EVERY (UINT64_C(1) << 26)

int main(void) {
    printf("fpu_spin pid: %d\n", getpid());
    fflush(stdout);

    volatile double step_source = 0.5;
    double step = step_source;

    v4df increment = {step, 2 * step, 3 * step, 4 * step};
    v4df accumulator = {0, 0, 0, 0};

    for (uint64_t n = 1;; n++) {
        accumulator += increment;

        if (n % REPORT_EVERY != 0)
            continue;

        int broken_lane = -1;
        for (int lane = 0; lane < 4; lane++) {
            double expected = (double)n * (lane + 1) * step;
            if (accumulator[lane] != expected) {
                broken_lane = lane;
                break;
            }
        }

        if (broken_lane < 0)
            printf("%llu ok\n", (unsigned long long)n);
        else
            printf("%llu BROKEN lane %d\n", (unsigned long long)n, broken_lane);
        fflush(stdout);
    }

    return 0;
}
