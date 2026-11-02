/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Subscriptions and data change notifications of the UDR, against a real HTTP/2 callback server. */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "g5c/testkit.h"
#include "g5c/udr.h"
#include "store_env.h"

typedef struct {
    int status;
    g5c_json *json;
    char location[256], cause[64];
} R;

static g5c_json *J(const char *s)
{
    g5c_json *j = g5c_json_parse(s, strlen(s), NULL, 0);
    TK_ASSERT(j != NULL);
    return j;
}

static R rq_h(g5c_router *rt, const char *method, const char *target, const char *body, const char *const *hdrs)
{
    g5c_req req;
    g5c_resp resp;
    const char *q = strchr(target, '?');
    R out;
    memset(&out, 0, sizeof out);
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = q ? g5c_xstrndup(target, (size_t)(q - target)) : g5c_xstrdup(target);
    req.query = q ? g5c_xstrdup(q + 1) : NULL;
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("udr.test:80");
    if (body != NULL)
        g5c_req_add_header(&req, "content-type", "application/json");
    for (size_t i = 0; hdrs != NULL && hdrs[i] != NULL; i += 2)
        g5c_req_add_header(&req, hdrs[i], hdrs[i + 1]);
    if (body != NULL)
        g5c_req_set_body(&req, body, strlen(body));
    g5c_resp_init(&resp);
    g5c_router_dispatch(rt, &req, &resp);
    out.status = resp.status;
    out.json = g5c_resp_parse_json(&resp);
    snprintf(out.location, sizeof out.location, "%s", g5c_resp_header_get(&resp, "location") ? g5c_resp_header_get(&resp, "location") : "");
    if (out.json != NULL && g5c_json_get_str(out.json, "cause") != NULL)
        snprintf(out.cause, sizeof out.cause, "%s", g5c_json_get_str(out.json, "cause"));
    g5c_resp_free(&resp);
    g5c_req_free(&req);
    return out;
}

static R rq(g5c_router *rt, const char *method, const char *target, const char *body)
{
    return rq_h(rt, method, target, body, NULL);
}

static void done(R *r)
{
    g5c_json_free(r->json);
    r->json = NULL;
}

/* ---- the consumer: a callback server that records what it is sent ------------------------------------------------- */

typedef struct {
    pthread_mutex_t mu;
    g5c_json *items[64];
    size_t n;
    int answer; /* status the consumer gives */
    size_t calls;
} sink_t;

static void cb_handler(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    sink_t *s = ctx;
    g5c_json *j = g5c_req_json(req, resp);
    pthread_mutex_lock(&s->mu);
    s->calls++;
    if (j != NULL && s->n < 64)
        s->items[s->n++] = j;
    else
        g5c_json_free(j);
    pthread_mutex_unlock(&s->mu);
    g5c_resp_init(resp);
    g5c_resp_status(resp, s->answer);
}

static const g5c_json *wait_item(sink_t *s, size_t idx, int ms)
{
    for (int i = 0; i < ms / 5; i++) {
        pthread_mutex_lock(&s->mu);
        if (s->n > idx) {
            const g5c_json *j = s->items[idx];
            pthread_mutex_unlock(&s->mu);
            return j;
        }
        pthread_mutex_unlock(&s->mu);
        usleep(5000);
    }
    return NULL;
}

static size_t count(sink_t *s)
{
    size_t n;
    pthread_mutex_lock(&s->mu);
    n = s->n;
    pthread_mutex_unlock(&s->mu);
    return n;
}

typedef struct {
    sink_t sink;
    g5c_router *cbr;
    g5c_server *srv;
    g5c_client *client;
    g5c_udr_store *store;
    g5c_router *r;
    g5c_registry *reg;
    char cb[96], root[64];
} Env;

static void env_start(Env *e, unsigned max_subs, unsigned retries)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    udr_opts o;
    memset(e, 0, sizeof *e);
    pthread_mutex_init(&e->sink.mu, NULL);
    e->sink.answer = 204;
    e->cbr = g5c_router_new();
    g5c_router_route(e->cbr, "POST", "/cb", cb_handler, &e->sink);
    e->srv = g5c_server_start(&cfg, e->cbr, NULL, 0);
    TK_ASSERT(e->srv != NULL);
    snprintf(e->cb, sizeof e->cb, "http://127.0.0.1:%u/cb", g5c_server_port(e->srv));
    e->client = g5c_client_new(2000, NULL);
    e->store = test_store_new();
    e->reg = g5c_registry_new();
    memset(&o, 0, sizeof o);
    o.ext_open = true;
    o.client = e->client;
    o.metrics = e->reg;
    o.max_subscriptions = max_subs;
    o.notify_retries = retries;
    snprintf(e->root, sizeof e->root, "http://udr.example:7790");
    o.api_root = e->root;
    e->r = g5c_udr_router_opts(e->store, &o);
}

static void env_stop(Env *e)
{
    g5c_router_free(e->r);
    g5c_udr_store_free(e->store); /* stops the delivery threads before the client goes */
    g5c_client_free(e->client);
    g5c_server_stop(e->srv);
    g5c_router_free(e->cbr);
    for (size_t i = 0; i < e->sink.n; i++)
        g5c_json_free(e->sink.items[i]);
    g5c_registry_free(e->reg);
}

#define sub_body(fmt, cb) g5c_xasprintf(fmt, cb)

#define SUB "/nudr-dr/v1/subscription-data/"

static void test_subscription_data(void)
{
    Env e;
    R x;
    char *body, sid[64];
    const g5c_json *n;
    env_start(&e, 0, 0);

    body = sub_body("{\"callbackReference\":\"%s\",\"ueId\":\"imsi-1\",\"monitoredResourceUris\":"
                    "[\"http://udr.example:7790/nudr-dr/v1/subscription-data/imsi-1/00101/provisioned-data/am-data\"],"
                    "\"originalCallbackReference\":\"http://udm.example/cb\",\"expiry\":\"2099-01-01T00:00:00Z\"}", e.cb);
    x = rq(e.r, "POST", SUB "subs-to-notify", body);
    free(body);
    TK_ASSERT(x.status == 201 && strstr(x.location, "/subscription-data/subs-to-notify/") != NULL);
    snprintf(sid, sizeof sid, "%s", g5c_json_get_str(x.json, "subscriptionId"));
    TK_ASSERT(sid[0] != '\0');
    {   /* the repository, not the consumer, decides the expiry: a day at most */
        const char *exp = g5c_json_get_str(x.json, "expiry");
        TK_ASSERT(exp != NULL && strcmp(exp, "2099-01-01T00:00:00Z") != 0);
    }
    done(&x);

    x = rq(e.r, "PUT", SUB "imsi-1/00101/provisioned-data/am-data", "{\"gpsis\":[\"msisdn-1\"]}");
    TK_ASSERT(x.status == 201);
    done(&x);
    n = wait_item(&e.sink, 0, 3000);
    TK_ASSERT(n != NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(n, "ueId"), "imsi-1") == 0);
    TK_ASSERT(strcmp(g5c_json_str(g5c_json_at(g5c_json_get(n, "originalCallbackReference"), 0)), "http://udm.example/cb") == 0);
    {
        const g5c_json *it = g5c_json_at(g5c_json_get(n, "notifyItems"), 0), *ch = g5c_json_at(g5c_json_get(it, "changes"), 0);
        TK_ASSERT(strstr(g5c_json_get_str(it, "resourceId"), "/imsi-1/00101/provisioned-data/am-data") != NULL);
        TK_ASSERT(strcmp(g5c_json_get_str(ch, "op"), "ADD") == 0 && strcmp(g5c_json_get_str(ch, "path"), "") == 0);
        TK_ASSERT(g5c_json_get(ch, "newValue") != NULL && g5c_json_get(ch, "origValue") == NULL);
    }

    /* a change of one member is reported as that member */
    x = rq(e.r, "PUT", SUB "imsi-1/00101/provisioned-data/am-data", "{\"gpsis\":[\"msisdn-2\"],\"subscribedUeAmbr\":{\"uplink\":\"1 Gbps\",\"downlink\":\"1 Gbps\"}}");
    TK_ASSERT(x.status == 204);
    done(&x);
    n = wait_item(&e.sink, 1, 3000);
    TK_ASSERT(n != NULL);
    {
        const g5c_json *chs = g5c_json_get(g5c_json_at(g5c_json_get(n, "notifyItems"), 0), "changes");
        bool seen_gpsi = false, seen_ambr = false;
        for (size_t i = 0; i < g5c_json_len(chs); i++) {
            const g5c_json *c = g5c_json_at(chs, i);
            if (strcmp(g5c_json_get_str(c, "path"), "/gpsis") == 0) {
                seen_gpsi = strcmp(g5c_json_get_str(c, "op"), "REPLACE") == 0 && g5c_json_get(c, "origValue") != NULL;
            } else if (strcmp(g5c_json_get_str(c, "path"), "/subscribedUeAmbr") == 0) {
                seen_ambr = strcmp(g5c_json_get_str(c, "op"), "ADD") == 0;
            }
        }
        TK_ASSERT(seen_gpsi && seen_ambr);
    }

    /* a write that names the subscription in 3gpp-Sbi-Notification-Correlation does not notify it */
    {
        char hdr[96];
        const char *h[] = {"3gpp-sbi-notification-correlation", hdr, NULL};
        snprintf(hdr, sizeof hdr, "other, %s,", sid);
        x = rq_h(e.r, "PUT", SUB "imsi-1/00101/provisioned-data/am-data", "{\"gpsis\":[\"msisdn-3\"]}", h);
        TK_ASSERT(x.status == 204);
        done(&x);
    }
    usleep(300000);
    TK_ASSERT(count(&e.sink) == 2);
    /* another subscriber's data is not monitored */
    x = rq(e.r, "PUT", SUB "imsi-2/00101/provisioned-data/am-data", "{\"gpsis\":[\"msisdn-9\"]}");
    TK_ASSERT(x.status == 201);
    done(&x);
    usleep(300000);
    TK_ASSERT(count(&e.sink) == 2);

    x = rq(e.r, "DELETE", SUB "imsi-1/00101/provisioned-data/am-data", NULL);
    TK_ASSERT(x.status == 204);
    done(&x);
    n = wait_item(&e.sink, 2, 3000);
    TK_ASSERT(n != NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(g5c_json_at(g5c_json_get(n, "notifyItems"), 0), "changes"), 0), "op"), "REMOVE") == 0);

    /* unsubscribe: the subscription can be read, and after its removal nothing more arrives */
    {
        char path[160];
        snprintf(path, sizeof path, SUB "subs-to-notify/%s", sid);
        x = rq(e.r, "GET", path, NULL);
        TK_ASSERT(x.status == 200 && strcmp(g5c_json_get_str(x.json, "subscriptionId"), sid) == 0);
        done(&x);
        x = rq(e.r, "DELETE", path, NULL);
        TK_ASSERT(x.status == 204);
        done(&x);
        x = rq(e.r, "DELETE", path, NULL);
        TK_ASSERT(x.status == 404);
        done(&x);
    }
    x = rq(e.r, "PUT", SUB "imsi-1/00101/provisioned-data/am-data", "{\"gpsis\":[\"msisdn-4\"]}");
    done(&x);
    usleep(300000);
    TK_ASSERT(count(&e.sink) == 3);
    env_stop(&e);
}

static void test_other_data_sets(void)
{
    Env e;
    R x;
    char *body;
    const g5c_json *n, *o;
    env_start(&e, 0, 0);

    /* policy data: an array of PolicyDataChangeNotification, the document in the member for its resource */
    body = sub_body("{\"notificationUri\":\"%s\",\"notifId\":\"n-1\",\"monitoredResourceUris\":"
                    "[\"http://udr.example:7790/nudr-dr/v1/policy-data/ues/imsi-5/operator-specific-data\"]}", e.cb);
    x = rq(e.r, "POST", "/nudr-dr/v1/policy-data/subs-to-notify", body);
    free(body);
    TK_ASSERT(x.status == 201);
    done(&x);
    x = rq(e.r, "PUT", "/nudr-dr/v1/policy-data/ues/imsi-5/operator-specific-data", "{\"k\":{\"dataType\":\"object\",\"value\":{\"a\":1}}}");
    TK_ASSERT(x.status == 201 || x.status == 204);
    done(&x);
    n = wait_item(&e.sink, 0, 3000);
    TK_ASSERT(n != NULL && g5c_json_is(n, G5C_J_ARRAY) && g5c_json_len(n) == 1);
    o = g5c_json_at(n, 0);
    TK_ASSERT(strcmp(g5c_json_get_str(o, "ueId"), "imsi-5") == 0 && strcmp(g5c_json_get_str(o, "notifId"), "n-1") == 0);
    TK_ASSERT(g5c_json_get(g5c_json_get(o, "opSpecDataMap"), "k") != NULL);
    x = rq(e.r, "DELETE", "/nudr-dr/v1/policy-data/ues/imsi-5/operator-specific-data", NULL);
    TK_ASSERT(x.status == 204);
    done(&x);
    n = wait_item(&e.sink, 1, 3000);
    TK_ASSERT(n != NULL);
    o = g5c_json_at(n, 0);
    TK_ASSERT(g5c_json_len(g5c_json_get(o, "delResources")) == 1 && g5c_json_get(o, "opSpecDataMap") == NULL);

    /* exposure data */
    body = sub_body("{\"notificationUri\":\"%s\",\"monitoredResourceUris\":"
                    "[\"http://udr.example:7790/nudr-dr/v1/exposure-data/imsi-6/access-and-mobility-data\"]}", e.cb);
    x = rq(e.r, "POST", "/nudr-dr/v1/exposure-data/subs-to-notify", body);
    free(body);
    TK_ASSERT(x.status == 201);
    done(&x);
    x = rq(e.r, "PUT", "/nudr-dr/v1/exposure-data/imsi-6/access-and-mobility-data", "{\"rfspIndex\":3}");
    TK_ASSERT(x.status == 201 || x.status == 200 || x.status == 204);
    done(&x);
    n = wait_item(&e.sink, 2, 3000);
    TK_ASSERT(n != NULL);
    o = g5c_json_at(n, 0);
    TK_ASSERT(strcmp(g5c_json_get_str(o, "ueId"), "imsi-6") == 0 && g5c_json_get(o, "accessAndMobilityData") != NULL);

    /* influence data: filter based; only the subscribed DNN is notified */
    body = sub_body("{\"notificationUri\":\"%s\",\"dnns\":[\"internet\"]}", e.cb);
    x = rq(e.r, "POST", "/nudr-dr/v1/application-data/influenceData/subs-to-notify", body);
    free(body);
    TK_ASSERT(x.status == 201);
    done(&x);
    x = rq(e.r, "PUT", "/nudr-dr/v1/application-data/influenceData/i1", "{\"afAppId\":\"app\",\"dnn\":\"ims\",\"supi\":\"imsi-1\"}");
    TK_ASSERT(x.status == 201);
    done(&x);
    usleep(300000);
    TK_ASSERT(count(&e.sink) == 3); /* ims is not subscribed */
    x = rq(e.r, "PUT", "/nudr-dr/v1/application-data/influenceData/i2", "{\"afAppId\":\"app\",\"dnn\":\"internet\",\"supi\":\"imsi-1\"}");
    TK_ASSERT(x.status == 201);
    done(&x);
    n = wait_item(&e.sink, 3, 3000);
    TK_ASSERT(n != NULL);
    o = g5c_json_at(n, 0);
    TK_ASSERT(strstr(g5c_json_get_str(o, "resUri"), "/nudr-dr/v2/application-data/influenceData/i2") != NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(o, "trafficInfluData"), "dnn"), "internet") == 0);

    /* application data: dataFilters by kind */
    body = sub_body("{\"notificationUri\":\"%s\",\"dataFilters\":[{\"dataInd\":\"BDT\"}]}", e.cb);
    x = rq(e.r, "POST", "/nudr-dr/v1/application-data/subs-to-notify", body);
    free(body);
    TK_ASSERT(x.status == 201);
    done(&x);
    env_stop(&e);
}

static void test_limits_expiry_and_failures(void)
{
    Env e;
    R x;
    char *body;
    /* the number of subscriptions is bounded */
    env_start(&e, 2, 0);
    for (int i = 0; i < 3; i++) {
        body = sub_body("{\"notificationUri\":\"%s\",\"dnns\":[\"internet\"]}", e.cb);
        x = rq(e.r, "POST", "/nudr-dr/v1/application-data/influenceData/subs-to-notify", body);
        free(body);
        TK_ASSERT(x.status == (i < 2 ? 201 : 429));
        done(&x);
    }
    /* a body without the mandatory members is refused */
    x = rq(e.r, "POST", "/nudr-dr/v1/policy-data/subs-to-notify", "{\"notifId\":\"x\"}");
    TK_ASSERT(x.status == 400);
    done(&x);
    env_stop(&e);

    /* an expired subscription is not notified */
    env_start(&e, 0, 0);
    {
        g5c_json *old = J("{\"notificationUri\":\"http://127.0.0.1:9/never\",\"monitoredResourceUris\":"
                          "[\"http://u/nudr-dr/v1/policy-data/ues/imsi-7/am-data\"],\"expiry\":\"2001-01-01T00:00:00Z\"}");
        TK_ASSERT(g5c_udr_put(e.store, "_", "policy-data/subs-to-notify/old", old));
    }
    x = rq(e.r, "PUT", "/nudr-dr/v1/policy-data/ues/imsi-7/operator-specific-data", "{\"k\":{\"dataType\":\"object\",\"value\":{}}}");
    done(&x);
    usleep(200000);
    TK_ASSERT(count(&e.sink) == 0);
    env_stop(&e);

    /* a consumer that fails is retried, then given up on; the outcome is counted */
    env_start(&e, 0, 1);
    e.sink.answer = 500;
    body = sub_body("{\"notificationUri\":\"%s\",\"monitoredResourceUris\":[\"http://u/nudr-dr/v1/policy-data/ues/imsi-8/am-data\"]}", e.cb);
    x = rq(e.r, "POST", "/nudr-dr/v1/policy-data/subs-to-notify", body);
    free(body);
    TK_ASSERT(x.status == 201);
    done(&x);
    x = rq(e.r, "PUT", "/nudr-dr/v1/policy-data/ues/imsi-8/am-data", "{\"subscCats\":[\"gold\"]}");
    TK_ASSERT(x.status == 201 || x.status == 204);
    done(&x);
    for (int i = 0; i < 400; i++) {
        char *m = g5c_registry_render(e.reg);
        bool failed = strstr(m, "g5c_udr_notifications_total{result=\"failed\"} 1") != NULL;
        free(m);
        if (failed)
            break;
        usleep(10000);
    }
    {
        char *m = g5c_registry_render(e.reg);
        TK_ASSERT(strstr(m, "g5c_udr_notifications_total{result=\"failed\"} 1") != NULL);
        free(m);
    }
    pthread_mutex_lock(&e.sink.mu);
    TK_ASSERT(e.sink.calls == 2); /* the first attempt and one retry */
    pthread_mutex_unlock(&e.sink.mu);
    env_stop(&e);
}

int main(void)
{
    g5c_log_init("error", false);
    test_subscription_data();
    test_other_data_sets();
    test_limits_expiry_and_failures();
    puts("udr notify: ok");
    return 0;
}
