#ifndef ZIG_OURA_H
#define ZIG_OURA_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Allocate oura_context_size() bytes aligned to oura_context_align(). Supply
 * independent scratch (65535 bytes covers the largest wire envelope).
 * A context is single-owner; independent contexts are safe on separate threads.
 * All output data is borrowed until the next call; copy/persist before accept.
 * Return: >=0 output kind, -1 malformed, -2 capacity, -3 unsupported,
 * -4 auth, -5 timeout, -6 state, -7 count, -8 incomplete, -9 ring rejection,
 * -10 overflow/size. No allocation, network, reset, or ring-history deletion.
 */
enum OuraOutputKind { OURA_NONE = 0, OURA_WRITE = 1, OURA_READY = 2,
    OURA_EVENT = 3, OURA_BATCH = 4, OURA_HEART_RATE = 5, OURA_PACKET = 6,
    OURA_UNSUPPORTED = 7, OURA_UNCONFIGURED = 8 };
/* For WRITE, auxiliary=1 marks sensitive payloads: never log them. */
typedef struct OuraContext OuraContext;
typedef struct {
    uint32_t kind, tag, timestamp_ds, count, bytes_left, auxiliary;
    uint64_t timestamp_ms;
    const uint8_t *data;
    size_t length;
    double value;
} OuraOutput;
typedef struct { uint32_t kind, index, interval_ms; double value; } OuraSample;
uint32_t oura_abi_version(void);
size_t oura_context_size(void);
size_t oura_context_align(void);
int32_t oura_context_init(OuraContext *, size_t, uint8_t *scratch, size_t);
int32_t oura_begin(OuraContext *, const uint8_t *key, size_t, uint64_t now_ms);
/* Only after kind 8, explicit consent and durable secure key storage. This
 * cannot overwrite an existing configured pairing or reset the ring. */
int32_t oura_install_key(OuraContext *, const uint8_t *key, size_t, uint64_t now_ms);
int32_t oura_sync(OuraContext *, uint32_t extended, uint32_t cursor, uint16_t limit, uint64_t now_ms);
int32_t oura_receive(OuraContext *, const uint8_t *, size_t, uint64_t now_ms);
int32_t oura_next(OuraContext *);
int32_t oura_accept(OuraContext *);
int32_t oura_commit(OuraContext *, uint32_t *cursor);
int32_t oura_tick(OuraContext *, uint64_t now_ms);
void oura_close(OuraContext *);
const OuraOutput *oura_output(OuraContext *);
size_t oura_consumed(OuraContext *);
int32_t oura_auth_result(OuraContext *);
int32_t oura_key_result(OuraContext *);
int32_t oura_decode_samples(uint8_t tag, const uint8_t *body, size_t, OuraSample *, size_t capacity);
/* 1 firmware, 2 battery, 3 serial, 4 capabilities(page), 5 latest(feature),
 * 6 feature mode(feature, mode), 7 stream subscription(mode 0/1/2),
 * 8 hardware ID, 9 event subscription(category, flags), 10 parameter(id),
 * 11 state poll, 13 data flush. */
int32_t oura_request(OuraContext *, uint32_t operation, uint32_t argument, uint32_t value);
#ifdef __cplusplus
}
#endif
#endif
