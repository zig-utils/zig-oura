#define _POSIX_C_SOURCE 200809L
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "oura.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(void) {
    assert(oura_abi_version() == 1);
    size_t alignment = oura_context_align(), size = oura_context_size();
    size_t allocation = (size + alignment - 1) / alignment * alignment;
    OuraContext *context = aligned_alloc(alignment, allocation);
    uint8_t scratch[65535], key[16] = {0};
    assert(context);
    assert(oura_context_init(NULL, size, scratch, sizeof scratch) == -1);
    assert(oura_context_init(context, size - 1, scratch, sizeof scratch) == -1);
    assert(oura_context_init(context, size, scratch, sizeof scratch) == 0);
    assert(oura_begin(context, key, sizeof key, 0) == 1);
    const OuraOutput *output = oura_output(context);
    const uint8_t request[] = {0x2f, 1, 0x2b};
    assert(output->length == sizeof request);
    assert(memcmp(output->data, request, sizeof request) == 0);
    const uint8_t nonce[] = {0x2f, 16, 0x2c, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    assert(oura_receive(context, nonce, sizeof nonce, 1) == 1);
    assert(oura_consumed(context) == sizeof nonce);
    assert(oura_output(context)->length == 19);
    const uint8_t accepted[] = {0x2f, 2, 0x2e, 0};
    assert(oura_receive(context, accepted, sizeof accepted, 2) == 2);
    assert(oura_auth_result(context) == 0);
    assert(oura_sync(context, 0, 100, 255, 3) == 1);
    const uint8_t event[] = {0x5d, 8, 110, 0, 0, 0, 60, 40, 62, 45};
    assert(oura_receive(context, event, sizeof event, 4) == 3);
    output = oura_output(context);
    assert(output->timestamp_ds == 110 && output->timestamp_ms == 11000);
    assert(output->tag == 0x5d && output->length == 4);
    OuraSample samples[8];
    assert(oura_decode_samples(output->tag, output->data, output->length, samples, 8) == 4);
    assert(samples[0].kind == 0 && samples[0].value == 60.0);
    assert(samples[1].kind == 1 && samples[1].value == 40.0);
    assert(samples[1].interval_ms == 300000);
    assert(oura_decode_samples(output->tag, output->data, output->length, samples, 1) == -2);
    uint32_t cursor = 100;
    assert(oura_commit(context, &cursor) == -6 && cursor == 100);
    assert(oura_accept(context) == 0);
    assert(oura_next(context) == 0);
    const uint8_t summary[] = {0x11, 6, 1, 0, 0, 0, 0, 0};
    assert(oura_receive(context, summary, sizeof summary, 5) == 4);
    output = oura_output(context);
    assert(output->count == 1 && output->timestamp_ds == 111);
    assert(oura_commit(context, &cursor) == 0 && cursor == 111);
    oura_close(context);
    assert(oura_tick(context, 6) == -6);
    for (size_t i = 0; i < sizeof scratch; ++i) assert(scratch[i] == 0);
    free(context);
    puts("Native C ABI: authentication, history, readings and checkpoint verified");
    if (getenv("OURA_BENCH")) {
        const uint8_t body[] = {60, 40, 62, 45};
        const unsigned iterations = 1000000;
        struct timespec start, end;
        volatile double checksum = 0;
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (unsigned i = 0; i < iterations; ++i) {
            int count = oura_decode_samples(0x5d, body, sizeof body, samples, 8);
            assert(count == 4);
            checksum += samples[0].value;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double nanoseconds = (double)(end.tv_sec - start.tv_sec) * 1000000000.0 + (double)(end.tv_nsec - start.tv_nsec);
        assert(checksum == (double)iterations * 60.0);
        printf("Native C ABI decode: %.2f ns/event, %u events, four readings/event\n", nanoseconds / iterations, iterations);
    }
    return 0;
}
