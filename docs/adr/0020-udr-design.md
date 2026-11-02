# ADR-0020: UDR design (Phase 7, third function; replaces the udr-lite shim)

Status: Accepted (2026-10-22)

## Decision
- **One generic engine, driven by the pinned OpenAPI files.** `tools/spec/gen_udr_api.py` reads the four published API files of TS 29.505 (subscription data) and TS 29.519
  (policy, exposure and application data) and writes `nf/udr/src/api_routes.gen.c` (one row per operation: method, path template, operation id, request and response
  schema, status codes, content types, `fields` support, storage key, whether the path is a collection) and `api_schemas.gen.c` (the schemas those operations reach,
  flattened to a compact JSON document). 176 operations and 444 schemas; both files are committed and `python tools/spec/gen_udr_api.py --check` fails when they are stale.
  Nothing about a resource is typed from memory. The engine registers every operation under `/nudr-dr/v1` and `/nudr-dr/v2` (TS 29.504 6.1.1 says v2; the 5G core
  consumers, ours and Open5GS's, use v1) and serves it the same way whatever the resource is.
- **Addressing.** A resource is its URI. The storage key is the path without the subscriber and without the serving PLMN (a repository holds the subscription of one PLMN),
  the partition is the subscriber (`{ueId}`), a group (`group:{ueGroupId}`) or the global one (`_`). A GPSI in the `{ueId}` position is resolved through an alias index
  that the identity data (`.../identity-data`, `gpsiList`) maintains.
- **Operations** (TS 29.504 5.2.2): GET (document; the children of a collection; the composite parents `ProvisionedDataSets` and `ContextDataSets` assembled from their
  members; `?fields=` JSON pointers, a bare member name taken as a pointer; the SM subscription filters `single-nssai` and `dnn`; the SM policy filters `snssai` and `dnn`),
  PUT (create: 201 with the representation and a Location; replace: 204, or 200 when the operation lists it), POST (collections: the identifier is allocated, 201, Location),
  PATCH (JSON Patch, and merge patch for `application/merge-patch+json`; atomic read-modify-write, the result is validated, a failing patch changes nothing), DELETE.
  **Entity tags and conditions** (6.1.2.2): a strong `ETag` (the revision), `Last-Modified`, `If-None-Match` and `If-Modified-Since` on GET (304), `If-Match` on
  PUT/PATCH/DELETE, `If-None-Match: *` on PUT (create only); a failed condition is 412 and changes nothing (the check is part of the storage operation, so it is atomic).
  `Cache-Control: max-age` is configurable. The `3gpp-Sbi-Notification-Correlation` header names subscriptions that a write does not notify (6.1.2.3.3).
- **Validation.** Request bodies, and the document that results from a PATCH, are checked against the schemas of the pinned files by a validator written for this
  (`nf/udr/src/schema.c`: type, nullable, enum, ranges, lengths, patterns, items, required, properties, additionalProperties, allOf / anyOf / oneOf). `oneOf` accepts when
  one alternative matches (the 3GPP schemas are open: two alternatives that differ by their `required` sets would both match a superset). References into specifications we
  have not pinned (TS 29.122, 29.514, 29.518, 29.522, 29.544, 29.551, 29.554, 29.572: 26 references, listed by the generator) accept anything. A body that fails is 400
  `MANDATORY_IE_INCORRECT` with the JSON pointer of the member that is wrong. `validate: false` switches it off.
- **Storage interface** (`udr_db`, `nf/udr/src/api.h`): get, put (with a precondition; returns the replaced record), delete, mutate (atomic read-modify-write), list a key
  prefix, partitions, delete a partition. Documents carry a revision (the entity tag) and a modification time. **Backends**: memory, memory with a snapshot and a journal
  (development, tests and small labs: write-behind journal, crash image recovery, the code of the shim), and **PostgreSQL** through libpq (`store.type: postgres`).
  ADR-0004 named SQLite for development; a journalled memory store needs no further dependency and was already proven, so SQLite is not used. The PostgreSQL schema is one
  table, `udr_doc(part, key COLLATE "C", doc jsonb, rev bigint, mtime bigint)`, primary key (part, key), revisions from a sequence (unique and increasing across replicas that
  share a database). Every mutation is a transaction that locks the row (`SELECT ... FOR UPDATE`), checks the precondition and writes, so two UDR replicas on one database
  behave like one process; a prefix listing is a range scan. A pool of connections serves the request threads; a lost connection is reset once. The schema carries a version
  and a UDR refuses a database of another version. The connection string (a secret) comes from `G5C_UDR_PG_CONNINFO` or a file, never from the configuration. The same
  conformance suite (`test_udr_db`) runs against all three backends, including eight threads doing read-modify-write on one document and eight creating one key.
- **Subscriptions and notifications** (5.2.2.6 - 5.2.2.8). A subscription is a document under `<data set>/subs-to-notify/<id>` created by the ordinary POST (subscription data:
  `SubscriptionDataSubscriptions`; policy, exposure: `PolicyDataSubscription`, `ExposureDataSubscription`; application data: `ApplicationDataSubs`; influence data:
  `TrafficInfluSub`). The UDR chooses the expiry (never more than `subscriptions.max_lifetime_s`, spread by up to 5 % so that subscriptions made together do not expire
  together), bounds the number per data set (429), and removes expired ones. Every write that succeeds calls the notifier, which matches the changed resource against the
  subscriptions of its data set (monitored resource URIs, resolved with the operation table, a parent resource covers its children; for application and influence data the
  filters `dnns`, `snssais`, `internalGroupIds`, `supis`, `appIds`) and queues a notification: `DataChangeNotify` with `NotifyItem` and `ChangeItem` (whole document ADD /
  REMOVE, else one item per member that changed; `originalCallbackReference` of a stateless UDM is carried), an array of `PolicyDataChangeNotification`,
  `ExposureDataChangeNotification`, `TrafficInfluDataNotif` or `ApplicationDataChangeNotif`. Worker threads deliver (2xx is success), retry with a back-off, drop a notification
  after the configured attempts, and a bounded queue protects the memory; a slow or dead consumer never delays the request that changed the data. The subscription list of a
  data set is cached for two seconds so that a write costs no query.
- **Provisioning extension.** TS 29.505 has no operation that creates the permanent subscription data (the resources are GET-only), removes a subscriber or lists them. The
  UDR offers `PUT` and `DELETE` on every GET-only resource (validated against the schema of its GET answer), `DELETE /subscription-data/{ueId}` and
  `GET /subscription-data` (the subscribers), protected by a bearer token (`provisioning.token_file` or `G5C_UDR_PROVISIONING_TOKEN`, 16 characters at least, compared in
  constant time). Without a token the extension answers 403 `PROVISIONING_DISABLED`. The operations that the specification does define need no token. The UDM presents the token
  (`udr.token_file` or `G5C_UDM_UDR_TOKEN`) with every request to the UDR; the consumers that only use the 3GPP operations (AMF, SMF, AUSF, PCF) do not.
- **Nudr_GroupIDmap** (`/nudr-group-id-map/v1/nf-group-ids`): the NF group of a subscriber by NF type, from the configured `group_ids` (NF type, group id, SUPI ranges); a GPSI
  is resolved to its SUPI first. The UDR registers `nudr-dr` (versions v1 and v2 as one service with two versions) and `nudr-group-id-map` with the NRF, with a `udrInfo`
  (group id, SUPI and GPSI ranges, supported data sets).
- **The PCF's policy document** moved from the opaque `policy-data/ues/{supi}/sm-data` of the shim to `policy-data/ues/{supi}/operator-specific-data` (a map of
  `OperatorSpecificDataContainer`, key `g5c-policy`, `dataType: object`), the container TS 29.519 provides for data it does not model. The resources `sm-data` and `am-data`
  now hold `SmPolicyData` and `AmPolicyData` as the specification defines them (Open5GS's PCF reads them).
- **Interoperability with Open5GS's consumers.** Open5GS's UDM accepts only 204 for the PUTs of authentication events, AMF and SMF registrations, where TS 29.504 5.2.2.3.2
  answers 201 when a resource is created; `compat.put_no_content: true` makes every successful PUT 204 (the Location header is still sent). S3 and S4 pass with Open5GS's
  UDM, AUSF, PCF, SMF and AMF against our UDR (`OUR_UDR=1`). Differences found on the way and kept: Open5GS's UDR returns `allowedSscModes` with three entries where the schema
  allows two (our validator refuses that document, so the oracle provisions a conforming one), puts the SM data of `ProvisionedDataSets` in an object instead of an array,
  has no GET for the registrations, answers 400 for unknown resource names (404 here) and 400 for an SM policy without a slice (the whole document here); and the slice differentiator
  FFFFFF is treated as "no SD" in every S-NSSAI comparison (TS 23.003 28.4.2), which Open5GS's UDM relies on. `udr_differential` compares both UDRs request by request
  (status, attribute sets) with every accepted difference written down with its reason.

## Gaps (recorded in the conformance matrix as UDR-GAP-01 ...)
- UDR-GAP-01: 26 schema references into specifications that are not pinned accept any value; downloading TS 29.122, 29.514, 29.518, 29.522, 29.544, 29.551, 29.554 and 29.572 needs the owner's permission.
- UDR-GAP-02: PFD change notifications (`ApplicationDataChangeNotif.pfdData` = TS 29.551 `PfdChangeNotification`) are not sent; `monResItems` of a policy data subscription is not supported.
- UDR-GAP-03: the implicit subscription of the UDM to permanent subscription data (5.2.2.6.1: the UDR selects a UDM through the NRF) is not implemented; subscriptions are explicit.
- UDR-GAP-04: no feature negotiation (`supportedFeatures` is stored, not negotiated); DELETE of a whole subscription collection by query filters is not implemented; `Retry-After`/priority
  handling of 3gpp-Sbi-Message-Priority is not.
- UDR-GAP-05: the group-data aggregates (`5g-vn-groups/internal`, `pp-profile-data`, `group-identifiers`) are stored documents, not derived from the groups.
- UDR-GAP-06: PostgreSQL: one database, no sharding or migration beyond schema version 1, the `g5c_udr_records` gauge counts this process's changes after start; replication and
  failover are the database's. A subscriber's partition cannot be deleted atomically with the documents of other partitions (aliases are removed first).
- UDR-GAP-07: OAuth2 access tokens are not checked on the producer side (the NF-wide gap NRF-GAP-04).

## Tests
`udr_api` (validation, status codes, ETag and every precondition, JSON and merge patch, `fields`, filters, composites, collections, aliases, provisioning access), `udr_notify`
(a real callback server: every kind of subscription and notification, suppression, expiry, limits, retry and give-up), `udr_db` (the storage interface on every backend),
`udr_config`, `udr_patch_store_routes` (JSON Patch RFC 6902 cases, store start-up failures, journal recovery), the same three suites on PostgreSQL (`udr_*_postgres`, a throw-away
server per test through `deploy/run/pg-temp.sh`; skipped when no server binaries exist), `fuzz_replay_udr`, 63 of 63 payloads valid against the OpenAPI schemas (19 UDR payloads),
`udr_differential` against Open5GS's UDR over MongoDB, oracle S3 / S4 with Open5GS's UDM, AUSF, PCF, SMF, AMF against our UDR, the cluster tests with a token-protected UDR.
