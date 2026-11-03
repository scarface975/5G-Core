/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Alarm and audit event streaming. Warnings, errors and every g5c_audit log line also go, as JSON, to a syslog collector (RFC 5424 over UDP, TCP or TLS)
 * and/or an HTTP collector (a POST of a JSON array). A bounded queue and one worker keep the logging threads from ever waiting on the network */
#ifndef G5C_EVENTS_H
#define G5C_EVENTS_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/config.h"
#include "g5c/metrics.h"

typedef struct g5c_events g5c_events;

/* `cfg` must outlive the object. NULL with err when the process already streams events, or the TLS material cannot be read. */
g5c_events *g5c_events_start(const g5c_events_cfg *cfg, const char *nf_name, const char *instance_id, g5c_registry *metrics, char *err, size_t errcap);
/* Removes the tap, gives the worker up to two seconds to deliver what is queued, frees everything. */
void g5c_events_stop(g5c_events *e);
/* Waits until everything queued so far was delivered or dropped; false on timeout. */
bool g5c_events_flush(g5c_events *e, int timeout_ms);

#endif
