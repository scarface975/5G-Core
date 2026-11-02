/* SPDX-License-Identifier: LicenseRef-Proprietary */
#ifndef G5C_UPF_RULES_H
#define G5C_UPF_RULES_H

#include "g5c/upf.h"

/* State shared by the Create/Update PDRs of one request: TEIDs chosen per CHOOSE ID, and the PDRs that need an answer. */
typedef struct {
    bool have[256];
    uint32_t teid[256];
    uint16_t created[64];
    size_t ncreated;
} upf_choose;

/* Each returns 0 or a PFCP cause value, with the offending IE type in *bad. */
int rules_create_pdr(upf *u, upf_session *s, const pfcp_ie *grp, upf_choose *ch, uint16_t *bad);
int rules_update_pdr(upf *u, upf_session *s, const pfcp_ie *grp, upf_choose *ch, uint16_t *bad);
int rules_remove_pdr(upf *u, upf_session *s, const pfcp_ie *grp, uint16_t *bad);
int rules_create_far(upf_session *s, const pfcp_ie *grp, uint16_t *bad);
int rules_update_far(upf *u, upf_session *s, const pfcp_ie *grp, bool sndem, uint16_t *bad);
int rules_remove_id(upf_session *s, const pfcp_ie *grp, uint16_t type, uint16_t idtype, uint16_t *bad);
int rules_create_qer(upf_session *s, const pfcp_ie *grp, double now, uint16_t *bad);
int rules_update_qer(upf_session *s, const pfcp_ie *grp, double now, uint16_t *bad);
int rules_create_urr(upf_session *s, const pfcp_ie *grp, double now, uint16_t *bad);
int rules_update_urr(upf_session *s, const pfcp_ie *grp, uint16_t *bad);
int rules_create_bar(upf_session *s, const pfcp_ie *grp, bool update, uint16_t *bad);
int rules_validate(upf_session *s, uint16_t *bad);

#endif
