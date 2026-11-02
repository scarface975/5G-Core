/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* JSON Web Tokens signed with ES256 (ECDSA P-256 + SHA-256, RFC 7515 / 7518 clause 3.4) in the JWS Compact Serialization */
#ifndef G5C_JWT_H
#define G5C_JWT_H

#include <stddef.h>

#include "g5c/json.h"

typedef struct g5c_jwt_key g5c_jwt_key;

/* A new P-256 key pair. NULL with err on failure. */
g5c_jwt_key *g5c_jwt_key_generate(char *err, size_t errcap);
/* Private key from / to a PEM file (the file is created with mode 0600). */
g5c_jwt_key *g5c_jwt_key_load_pem(const char *path, char *err, size_t errcap);
int g5c_jwt_key_save_pem(const g5c_jwt_key *k, const char *path, char *err, size_t errcap);
/* Public key only, from a JWK ({"kty":"EC","crv":"P-256","x":..,"y":..}); such a key can verify but not sign. */
g5c_jwt_key *g5c_jwt_key_from_jwk(const g5c_json *jwk, char *err, size_t errcap);
/* The public key as a JWK (with "kid" and "use":"sig" and "alg":"ES256"). Caller frees. */
g5c_json *g5c_jwt_key_jwk(const g5c_jwt_key *k, const char *kid);
/* The JWK thumbprint of the public key (RFC 7638 */
char *g5c_jwt_key_thumbprint(const g5c_jwt_key *k);
void g5c_jwt_key_free(g5c_jwt_key *k);

/* Header {"alg":"ES256","typ":"JWT","kid":kid}, the claims as payload; the compact string, malloc'd (NULL on failure or for a public-only key). */
char *g5c_jwt_sign(const g5c_jwt_key *k, const char *kid, const g5c_json *claims);
/* Checks structure, algorithm and signature (not the claims) and returns the payload JSON (caller frees), or NULL with err. */
g5c_json *g5c_jwt_verify(const g5c_jwt_key *k, const char *token, char *err, size_t errcap);

#endif
