/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The few SCTP socket API items the N2 transport needs (RFC 6458 sections 5.3.4, 5.3.5 and 8.1.7), with the values of the Linux kernel UAPI */
#ifndef G5C_AMF_SCTP_ABI_H
#define G5C_AMF_SCTP_ABI_H

#include <netinet/in.h>
#include <stdint.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#define SCTP_NODELAY 3      /* setsockopt level IPPROTO_SCTP */
#define SCTP_RECVRCVINFO 32 /* deliver an SCTP_RCVINFO control message with every received message */
#define SCTP_DELAYED_SACK 16 /* delayed acknowledgement parameters (RFC 6458 8.1.19) */
struct sctp_sack_info {
    int32_t sack_assoc_id;
    uint32_t sack_delay; /* ms */
    uint32_t sack_freq;  /* packets per SACK; 1 = every packet */
};
#define SCTP_SNDINFO 2      /* cmsg type on send */
#define SCTP_RCVINFO 3      /* cmsg type on receive */
#ifndef MSG_NOTIFICATION
#define MSG_NOTIFICATION 0x8000 /* recvmsg msg_flags: the data is an association notification, not a user message */
#endif

struct sctp_sndinfo {
    uint16_t snd_sid;
    uint16_t snd_flags;
    uint32_t snd_ppid; /* network byte order */
    uint32_t snd_context;
    int32_t snd_assoc_id;
};

struct sctp_rcvinfo {
    uint16_t rcv_sid;
    uint16_t rcv_ssn;
    uint16_t rcv_flags;
    uint32_t rcv_ppid;
    uint32_t rcv_tsn;
    uint32_t rcv_cumtsn;
    uint32_t rcv_context;
    int32_t rcv_assoc_id;
};

_Static_assert(sizeof(struct sctp_sndinfo) == 16, "struct sctp_sndinfo layout (kernel UAPI)");
_Static_assert(sizeof(struct sctp_rcvinfo) == 28, "struct sctp_rcvinfo layout (kernel UAPI)");

#endif
