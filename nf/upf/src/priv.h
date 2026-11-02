/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Internal declarations shared by the UPF engine's translation units. */
#ifndef G5C_UPF_PRIV_H
#define G5C_UPF_PRIV_H

#include <stdlib.h>
#include <string.h>

#include "g5c/base.h"
#include "g5c/upf.h"

/* u64 -> pointer, open addressing with backward-shift deletion */
typedef struct upf_ptrmap upf_ptrmap;
upf_ptrmap *ptrmap_new(void);
void ptrmap_free(upf_ptrmap *m);
void *ptrmap_get(const upf_ptrmap *m, uint64_t key);
void ptrmap_put(upf_ptrmap *m, uint64_t key, void *val);
void ptrmap_del(upf_ptrmap *m, uint64_t key);
size_t ptrmap_len(const upf_ptrmap *m);

#define UPF_NTP_UNIX_OFFSET 2208988800u

/* sessions / rules (rules.c) */
upf_far *sess_find_far(upf_session *s, uint32_t id);
upf_qer *sess_find_qer(upf_session *s, uint32_t id);
upf_urr *sess_find_urr(upf_session *s, uint32_t id);
upf_bar *sess_find_bar(upf_session *s, uint8_t id);
upf_pdr *sess_find_pdr(upf_session *s, uint16_t id);
void sess_free(upf *u, upf_session *s);   /* unregister from every index and free */
void sess_unindex(upf *u, upf_session *s);
void sess_index_pdr(upf *u, upf_session *s, upf_pdr *p);
void bucket_init(upf_bucket *b, uint64_t kbps, double now);
void qer_rebuild(upf_qer *q, double now);
void upf_session_delete(upf *u, upf_session *s);

/* N4 message handling (n4.c) */
void n4_peer_down(upf *u, uint32_t peer_index);
upf_peer *n4_find_peer(upf *u, const upf_addr *a);
void n4_send(upf *u, const upf_addr *to, const uint8_t *msg, size_t len);
void n4_timers(upf *u, double now);
void n4_send_session_report(upf *u, upf_session *s, uint8_t report_type, const uint16_t *dl_pdr, const upf_urr *urr, uint32_t trigger);

/* usage reporting (urr.c) */
size_t urr_build_report(const upf *u, upf_urr *r, uint16_t group_type, uint32_t trigger, uint8_t *out, size_t cap, bool reset);
void urr_account(upf *u, upf_session *s, const upf_pdr *p, bool ul, size_t bytes, double now);
void urr_tick(upf *u, double now);

/* datapath (dp.c) */
void dp_flush_buffer(upf *u, upf_session *s, double now);
void dp_buffer_expire(upf *u, double now);
void dp_send_end_marker(upf *u, const upf_far *f);
void dp_drop_buffer(upf_session *s);

static inline void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

#endif
