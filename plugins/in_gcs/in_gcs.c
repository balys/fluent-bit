/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * in_gcs: read log objects from Google Cloud Storage as they are written.
 *
 * The bucket publishes OBJECT_FINALIZE notifications to a Pub/Sub topic. The
 * plugin pulls a subscription of that topic, downloads each object (gzip is
 * detected by its magic bytes), splits it into lines and appends one record
 * per line. A notification is acknowledged only after all of its records were
 * appended, so a crash or a failed append redelivers the object instead of
 * losing it (use 'storage.type filesystem' to survive restarts).
 */

#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_strptime.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>

#include <msgpack.h>
#include <ctype.h>
#include <string.h>

#include "in_gcs.h"

static msgpack_object *map_lookup(msgpack_object *map, const char *key)
{
    size_t i;
    size_t key_len;
    msgpack_object *k;

    if (!map || map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    key_len = strlen(key);
    for (i = 0; i < map->via.map.size; i++) {
        k = &map->via.map.ptr[i].key;
        if (k->type == MSGPACK_OBJECT_STR && k->via.str.size == key_len &&
            strncmp(k->via.str.ptr, key, key_len) == 0) {
            return &map->via.map.ptr[i].val;
        }
    }

    return NULL;
}

static int map_lookup_str(msgpack_object *map, const char *key,
                          const char **out, size_t *out_len)
{
    msgpack_object *v;

    v = map_lookup(map, key);
    if (!v || v->type != MSGPACK_OBJECT_STR || v->via.str.size == 0) {
        return -1;
    }
    *out = v->via.str.ptr;
    *out_len = v->via.str.size;

    return 0;
}

/* Percent-encode everything except RFC 3986 unreserved characters. */
static flb_sds_t uri_encode(const char *str, size_t len)
{
    size_t i;
    unsigned char c;
    flb_sds_t out;
    flb_sds_t tmp;
    char hex[4];

    out = flb_sds_create_size(len * 3 + 1);
    if (!out) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        c = (unsigned char) str[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            tmp = flb_sds_cat(out, (char *) &c, 1);
        }
        else {
            snprintf(hex, sizeof(hex), "%%%02X", c);
            tmp = flb_sds_cat(out, hex, 3);
        }
        if (!tmp) {
            flb_sds_destroy(out);
            return NULL;
        }
        out = tmp;
    }

    return out;
}

/* Parse an RFC 3339 UTC time such as 2026-01-02T03:04:05.123456Z */
static int parse_rfc3339(const char *str, size_t len, struct flb_time *out)
{
    int digits = 0;
    long nsec = 0;
    char buf[64];
    char *p;
    struct flb_tm tm;

    if (len == 0 || len >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, str, len);
    buf[len] = '\0';

    memset(&tm, 0, sizeof(tm));
    p = flb_strptime(buf, "%Y-%m-%dT%H:%M:%S", &tm);
    if (!p) {
        return -1;
    }
    if (*p == '.') {
        p++;
        while (isdigit((unsigned char) *p)) {
            if (digits < 9) {
                nsec = nsec * 10 + (*p - '0');
                digits++;
            }
            p++;
        }
        while (digits < 9) {
            nsec *= 10;
            digits++;
        }
    }
    if (*p != 'Z' && *p != 'z' && *p != '\0') {
        return -1;
    }

    out->tm.tv_sec = flb_parser_tm2time(&tm, FLB_FALSE);
    out->tm.tv_nsec = nsec;

    return 0;
}

static int endpoint_init(struct flb_in_gcs *ctx, struct flb_config *config,
                         const char *url, struct flb_in_gcs_endpoint *ep)
{
    int ret;
    int io_flags;
    size_t len;
    char *protocol = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;

    ret = flb_utils_url_split(url, &protocol, &host, &port, &uri);
    if (ret != 0 || !host || !port) {
        flb_plg_error(ctx->ins, "invalid endpoint URL '%s'", url);
        ret = -1;
        goto done;
    }

    if (strcasecmp(protocol, "https") == 0) {
        if (!ctx->ins->tls) {
            flb_plg_error(ctx->ins, "endpoint '%s' needs TLS but 'tls' is off", url);
            ret = -1;
            goto done;
        }
        io_flags = FLB_IO_TLS;
    }
    else if (strcasecmp(protocol, "http") == 0) {
        io_flags = FLB_IO_TCP;
    }
    else {
        flb_plg_error(ctx->ins, "unsupported scheme in endpoint '%s'", url);
        ret = -1;
        goto done;
    }

    /* keep the path as a prefix for every request, without a trailing slash */
    len = strlen(uri);
    while (len > 0 && uri[len - 1] == '/') {
        len--;
    }
    ep->base_uri = flb_sds_create_len(uri, len);
    if (!ep->base_uri) {
        ret = -1;
        goto done;
    }

    ep->u = flb_upstream_create(config, host, atoi(port), io_flags,
                                io_flags == FLB_IO_TLS ? ctx->ins->tls : NULL);
    if (!ep->u) {
        flb_plg_error(ctx->ins, "cannot create upstream for '%s'", url);
        ret = -1;
        goto done;
    }

    /* the collector runs in the plugin thread, outside of a coroutine */
    flb_stream_disable_async_mode(&ep->u->base);
    flb_input_upstream_set(ep->u, ctx->ins);
    ret = 0;

done:
    flb_free(protocol);
    flb_free(host);
    flb_free(port);
    flb_free(uri);

    return ret;
}

/*
 * Run one API request. On success the caller owns the returned client and
 * connection. 'too_large' is set when the response exceeded 'max_size'.
 */
static struct flb_http_client *api_call(struct flb_in_gcs *ctx,
                                        struct flb_in_gcs_endpoint *ep,
                                        int method, const char *uri,
                                        const char *body, size_t body_len,
                                        size_t max_size, int *too_large,
                                        struct flb_connection **out_conn)
{
    int ret;
    size_t bytes_sent;
    flb_sds_t auth = NULL;
    struct flb_connection *conn;
    struct flb_http_client *c;

    if (too_large) {
        *too_large = FLB_FALSE;
    }

    if (in_gcs_auth_header(ctx, &auth) != 0) {
        flb_plg_error(ctx->ins, "cannot get an access token");
        return NULL;
    }

    conn = flb_upstream_conn_get(ep->u);
    if (!conn) {
        flb_plg_error(ctx->ins, "cannot connect to %s:%i",
                      ep->u->tcp_host, ep->u->tcp_port);
        flb_sds_destroy(auth);
        return NULL;
    }

    c = flb_http_client(conn, method, uri, body, body_len, NULL, 0, NULL, 0);
    if (!c) {
        flb_upstream_conn_release(conn);
        flb_sds_destroy(auth);
        return NULL;
    }

    flb_http_buffer_size(c, max_size);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    if (ep == &ctx->storage) {
        /*
         * Download gzip objects as stored instead of letting GCS decompress
         * them (decompressive transcoding); they are gunzipped here.
         */
        flb_http_add_header(c, "Accept-Encoding", 15, "gzip", 4);
    }
    if (body) {
        flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    }
    if (auth) {
        flb_http_add_header(c, "Authorization", 13, auth, flb_sds_len(auth));
        flb_sds_destroy(auth);
    }

    ret = flb_http_do(c, &bytes_sent);
    if (ret != 0) {
        if (too_large && c->resp.data_size_max > 0 &&
            c->resp.data_size >= c->resp.data_size_max) {
            *too_large = FLB_TRUE;
        }
        else {
            flb_plg_warn(ctx->ins, "request failed: %s %s", ep->u->tcp_host, uri);
        }
        flb_http_client_destroy(c);
        flb_upstream_conn_release(conn);
        return NULL;
    }

    if (c->resp.status == 401) {
        in_gcs_auth_invalidate(ctx);
    }

    *out_conn = conn;
    return c;
}

static void api_done(struct flb_http_client *c, struct flb_connection *conn)
{
    flb_http_client_destroy(c);
    flb_upstream_conn_release(conn);
}

/* ':acknowledge' when deadline < 0, else ':modifyAckDeadline' */
static int pubsub_ack(struct flb_in_gcs *ctx, msgpack_object **ack_ids, int count,
                      int deadline)
{
    int i;
    int ret = -1;
    flb_sds_t uri;
    flb_sds_t json;
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    struct flb_connection *conn;
    struct flb_http_client *c;

    if (count == 0) {
        return 0;
    }

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pck, deadline < 0 ? 1 : 2);
    msgpack_pack_str_with_body(&pck, "ackIds", 6);
    msgpack_pack_array(&pck, count);
    for (i = 0; i < count; i++) {
        msgpack_pack_object(&pck, *ack_ids[i]);
    }
    if (deadline >= 0) {
        msgpack_pack_str_with_body(&pck, "ackDeadlineSeconds", 18);
        msgpack_pack_int(&pck, deadline);
    }
    json = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size, FLB_FALSE);
    msgpack_sbuffer_destroy(&sbuf);
    if (!json) {
        return -1;
    }

    uri = flb_sds_create_size(256);
    if (!uri || !flb_sds_printf(&uri, "%s/v1/%s:%s", ctx->pubsub.base_uri,
                                ctx->subscription_path,
                                deadline < 0 ? "acknowledge" : "modifyAckDeadline")) {
        flb_sds_destroy(uri);
        flb_sds_destroy(json);
        return -1;
    }

    c = api_call(ctx, &ctx->pubsub, FLB_HTTP_POST, uri, json, flb_sds_len(json),
                 FLB_IN_GCS_API_BUFFER_MAX, NULL, &conn);
    if (c) {
        if (c->resp.status == 200) {
            ret = 0;
        }
        else {
            flb_plg_error(ctx->ins, "pubsub %s failed: status=%i %.*s",
                          deadline < 0 ? "acknowledge" : "modifyAckDeadline",
                          c->resp.status, (int) c->resp.payload_size,
                          c->resp.payload ? c->resp.payload : "");
        }
        api_done(c, conn);
    }

    flb_sds_destroy(uri);
    flb_sds_destroy(json);

    return ret;
}

/* Pull a batch of notifications; returns the response packed as msgpack. */
static int pubsub_pull(struct flb_in_gcs *ctx, char **out_buf, size_t *out_size)
{
    int ret = -1;
    int root_type;
    size_t consumed;
    char body[96];
    flb_sds_t uri;
    struct flb_connection *conn;
    struct flb_http_client *c;

    *out_buf = NULL;
    *out_size = 0;

    /*
     * returnImmediately keeps the plugin thread responsive to pause and
     * shutdown; the collector interval acts as the long-poll replacement.
     */
    snprintf(body, sizeof(body), "{\"maxMessages\":%i,\"returnImmediately\":true}",
             ctx->max_messages);

    uri = flb_sds_create_size(256);
    if (!uri || !flb_sds_printf(&uri, "%s/v1/%s:pull", ctx->pubsub.base_uri,
                                ctx->subscription_path)) {
        flb_sds_destroy(uri);
        return -1;
    }

    c = api_call(ctx, &ctx->pubsub, FLB_HTTP_POST, uri, body, strlen(body),
                 FLB_IN_GCS_API_BUFFER_MAX * 4, NULL, &conn);
    flb_sds_destroy(uri);
    if (!c) {
        return -1;
    }

    if (c->resp.status != 200) {
        flb_plg_error(ctx->ins, "pubsub pull failed: status=%i %.*s",
                      c->resp.status, (int) c->resp.payload_size,
                      c->resp.payload ? c->resp.payload : "");
    }
    else if (c->resp.payload_size > 0) {
        ret = flb_pack_json(c->resp.payload, c->resp.payload_size,
                            out_buf, out_size, &root_type, &consumed);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "invalid pubsub pull response");
            ret = -1;
        }
    }
    else {
        ret = 0;
    }

    api_done(c, conn);

    return ret;
}

static int encoder_flush(struct flb_in_gcs *ctx)
{
    int ret = 0;

    if (ctx->encoder->output_length > 0) {
        ret = flb_input_log_append(ctx->ins, NULL, 0, ctx->encoder->output_buffer,
                                   ctx->encoder->output_length);
    }
    flb_log_event_encoder_reset(ctx->encoder);

    return ret;
}

static int encode_line(struct flb_in_gcs *ctx, const char *line, size_t len,
                       const char *name, size_t name_len, struct flb_time *prev_time)
{
    int i;
    int ret;
    int parsed = FLB_FALSE;
    void *out_buf = NULL;
    size_t out_size = 0;
    size_t off = 0;
    size_t k;
    struct flb_time t;
    msgpack_unpacked result;
    msgpack_object *map;

    /* the first parser that matches decides the timestamp and, maybe, the body */
    for (i = 0; i < ctx->parser_count; i++) {
        flb_time_zero(&t);
        ret = flb_parser_do(ctx->parsers[i], line, len, &out_buf, &out_size, &t);
        if (ret >= 0) {
            parsed = FLB_TRUE;
            if (flb_time_to_nanosec(&t) != 0) {
                flb_time_copy(prev_time, &t);
            }
            break;
        }
    }

    ret = flb_log_event_encoder_begin_record(ctx->encoder);
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_timestamp(ctx->encoder, prev_time);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS && parsed && !ctx->raw_line) {
        msgpack_unpacked_init(&result);
        if (msgpack_unpack_next(&result, out_buf, out_size, &off) ==
            MSGPACK_UNPACK_SUCCESS && result.data.type == MSGPACK_OBJECT_MAP) {
            map = &result.data;
            for (k = 0; k < map->via.map.size && ret == FLB_EVENT_ENCODER_SUCCESS; k++) {
                ret = flb_log_event_encoder_append_body_msgpack_object(
                        ctx->encoder, &map->via.map.ptr[k].key);
                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_append_body_msgpack_object(
                            ctx->encoder, &map->via.map.ptr[k].val);
                }
            }
        }
        else {
            parsed = FLB_FALSE;
        }
        msgpack_unpacked_destroy(&result);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS && (!parsed || ctx->raw_line)) {
        ret = flb_log_event_encoder_append_body_values(
                ctx->encoder,
                FLB_LOG_EVENT_CSTRING_VALUE(ctx->key),
                FLB_LOG_EVENT_STRING_VALUE(line, len));
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS && ctx->object_key) {
        ret = flb_log_event_encoder_append_body_values(
                ctx->encoder,
                FLB_LOG_EVENT_CSTRING_VALUE(ctx->object_key),
                FLB_LOG_EVENT_STRING_VALUE(name, name_len));
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->encoder);
    }
    else {
        flb_log_event_encoder_rollback_record(ctx->encoder);
    }

    if (out_buf) {
        flb_free(out_buf);
    }

    return ret == FLB_EVENT_ENCODER_SUCCESS ? 0 : -1;
}

/* Split the object into lines and append them; the object is read-only here. */
static int process_lines(struct flb_in_gcs *ctx, const char *data, size_t size,
                         const char *name, size_t name_len,
                         struct flb_time *fallback, size_t *out_lines)
{
    size_t len;
    const char *p;
    const char *end;
    const char *nl;
    struct flb_time prev_time;

    flb_time_copy(&prev_time, fallback);
    flb_log_event_encoder_reset(ctx->encoder);
    *out_lines = 0;

    p = data;
    end = data + size;
    while (p < end) {
        nl = memchr(p, '\n', end - p);
        len = nl ? (size_t) (nl - p) : (size_t) (end - p);
        if (len > 0 && p[len - 1] == '\r') {
            len--;
        }

        if (len > 0) {
            if (encode_line(ctx, p, len, name, name_len, &prev_time) != 0) {
                flb_plg_error(ctx->ins, "cannot encode a line of '%.*s'",
                              (int) name_len, name);
                flb_log_event_encoder_reset(ctx->encoder);
                return -1;
            }
            (*out_lines)++;

            if (ctx->encoder->output_length >= FLB_IN_GCS_APPEND_SIZE &&
                encoder_flush(ctx) != 0) {
                return -1;
            }
        }

        p = nl ? nl + 1 : end;
    }

    return encoder_flush(ctx);
}

/* Decompress one or more concatenated gzip members. */
static int gunzip_all(struct flb_in_gcs *ctx, const char *data, size_t size,
                      char **out, size_t *out_size)
{
    int ret;
    char *buf = NULL;
    char *tmp;
    void *member;
    size_t member_size;
    size_t remaining;
    size_t total = 0;
    size_t off = 0;

    while (off < size) {
        remaining = 0;
        ret = flb_gzip_uncompress_multi((void *) (data + off), size - off,
                                        &member, &member_size, &remaining);
        if (ret != 0) {
            flb_free(buf);
            return -1;
        }

        if (total + member_size > ctx->buffer_max_size) {
            flb_plg_error(ctx->ins, "decompressed object exceeds buffer_max_size");
            flb_free(member);
            flb_free(buf);
            return -1;
        }

        tmp = flb_realloc(buf, total + member_size + 1);
        if (!tmp) {
            flb_errno();
            flb_free(member);
            flb_free(buf);
            return -1;
        }
        buf = tmp;
        memcpy(buf + total, member, member_size);
        total += member_size;
        flb_free(member);

        if (remaining == 0 || remaining >= size - off) {
            break;
        }
        off = size - remaining;
        /* trailing bytes that are not another gzip member are ignored */
        if (size - off < 2 || (unsigned char) data[off] != 0x1f ||
            (unsigned char) data[off + 1] != 0x8b) {
            break;
        }
    }

    *out = buf;
    *out_size = total;

    return 0;
}

/* Take a time from the object name, e.g. from 'dt=2024-01-31/hour=23'. */
static void object_time(struct flb_in_gcs *ctx, const char *name, size_t name_len,
                        struct flb_time *out)
{
    int ret;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time t;

    flb_time_zero(&t);
    ret = flb_parser_do(ctx->object_time_parser, name, name_len, &out_buf, &out_size, &t);
    if (ret >= 0 && flb_time_to_nanosec(&t) != 0) {
        flb_time_copy(out, &t);
    }
    flb_free(out_buf);
}

static int process_message(struct flb_in_gcs *ctx, msgpack_object *received)
{
    int ret;
    int too_large;
    const char *bucket;
    const char *name;
    const char *generation;
    const char *event_type;
    const char *event_time;
    size_t bucket_len;
    size_t name_len;
    size_t generation_len;
    size_t event_type_len;
    size_t event_time_len;
    size_t lines = 0;
    char *plain = NULL;
    size_t plain_size = 0;
    const char *data;
    size_t data_size;
    flb_sds_t uri = NULL;
    flb_sds_t enc_bucket = NULL;
    flb_sds_t enc_name = NULL;
    struct flb_time fallback;
    struct flb_connection *conn;
    struct flb_http_client *c;
    msgpack_object *message;
    msgpack_object *attrs;

    message = map_lookup(received, "message");
    attrs = map_lookup(message, "attributes");

    if (map_lookup_str(attrs, "eventType", &event_type, &event_type_len) != 0 ||
        event_type_len != 15 || strncmp(event_type, "OBJECT_FINALIZE", 15) != 0) {
        /* deletes, metadata updates and foreign messages carry no new data */
        return FLB_IN_GCS_ACK;
    }

    if (map_lookup_str(attrs, "bucketId", &bucket, &bucket_len) != 0 ||
        map_lookup_str(attrs, "objectId", &name, &name_len) != 0) {
        flb_plg_warn(ctx->ins, "notification without bucketId/objectId, skipping");
        return FLB_IN_GCS_ACK;
    }
    if (map_lookup_str(attrs, "objectGeneration", &generation, &generation_len) != 0) {
        generation = NULL;
        generation_len = 0;
    }

    /*
     * Lines without their own timestamp inherit the previous one, else the time
     * in the object name, else the notification time. Never the current time:
     * a backfilled object would move its stream to 'now' and Loki would then
     * reject its older lines.
     */
    flb_time_get(&fallback);
    if (map_lookup_str(attrs, "eventTime", &event_time, &event_time_len) == 0) {
        parse_rfc3339(event_time, event_time_len, &fallback);
    }
    if (ctx->object_time_parser) {
        object_time(ctx, name, name_len, &fallback);
    }

    enc_bucket = uri_encode(bucket, bucket_len);
    enc_name = uri_encode(name, name_len);
    uri = flb_sds_create_size(256 + name_len * 3);
    if (!enc_bucket || !enc_name || !uri) {
        ret = FLB_IN_GCS_RETRY;
        goto done;
    }
    if (!flb_sds_printf(&uri, "%s/storage/v1/b/%s/o/%s?alt=media",
                        ctx->storage.base_uri, enc_bucket, enc_name) ||
        (generation && !flb_sds_printf(&uri, "&generation=%.*s",
                                       (int) generation_len, generation))) {
        ret = FLB_IN_GCS_RETRY;
        goto done;
    }

    c = api_call(ctx, &ctx->storage, FLB_HTTP_GET, uri, NULL, 0,
                 ctx->buffer_max_size, &too_large, &conn);
    if (!c) {
        if (too_large) {
            flb_plg_error(ctx->ins, "gs://%.*s/%.*s is larger than buffer_max_size "
                          "(%zu), skipping it", (int) bucket_len, bucket,
                          (int) name_len, name, ctx->buffer_max_size);
            ret = FLB_IN_GCS_ACK;
        }
        else {
            ret = FLB_IN_GCS_RETRY;
        }
        goto done;
    }

    if (c->resp.status == 404) {
        flb_plg_warn(ctx->ins, "gs://%.*s/%.*s#%.*s no longer exists, skipping",
                     (int) bucket_len, bucket, (int) name_len, name,
                     (int) generation_len, generation ? generation : "");
        api_done(c, conn);
        ret = FLB_IN_GCS_ACK;
        goto done;
    }
    if (c->resp.status != 200) {
        flb_plg_error(ctx->ins, "download of gs://%.*s/%.*s failed: status=%i",
                      (int) bucket_len, bucket, (int) name_len, name, c->resp.status);
        api_done(c, conn);
        ret = FLB_IN_GCS_RETRY;
        goto done;
    }

    data = c->resp.payload;
    data_size = c->resp.payload_size;
    if (data_size >= 2 && (unsigned char) data[0] == 0x1f &&
        (unsigned char) data[1] == 0x8b) {
        if (gunzip_all(ctx, data, data_size, &plain, &plain_size) != 0) {
            flb_plg_error(ctx->ins, "gs://%.*s/%.*s is not valid gzip, skipping it",
                          (int) bucket_len, bucket, (int) name_len, name);
            api_done(c, conn);
            ret = FLB_IN_GCS_ACK;
            goto done;
        }
        data = plain;
        data_size = plain_size;
    }

    ret = process_lines(ctx, data, data_size, name, name_len, &fallback, &lines);
    api_done(c, conn);
    if (ret != 0) {
        /* partially appended objects are redelivered; Loki drops exact duplicates */
        flb_plg_warn(ctx->ins, "cannot append gs://%.*s/%.*s, will retry",
                     (int) bucket_len, bucket, (int) name_len, name);
        ret = FLB_IN_GCS_RETRY;
        goto done;
    }

    flb_plg_debug(ctx->ins, "gs://%.*s/%.*s: %zu lines",
                  (int) bucket_len, bucket, (int) name_len, name, lines);
    ret = FLB_IN_GCS_ACK;

done:
    flb_free(plain);
    flb_sds_destroy(uri);
    flb_sds_destroy(enc_bucket);
    flb_sds_destroy(enc_name);

    return ret;
}

static int cb_gcs_collect(struct flb_input_instance *ins,
                          struct flb_config *config, void *in_context)
{
    int i;
    int ret;
    int count;
    int acked = 0;
    int retried = 0;
    int n_ack = 0;
    int n_retry = 0;
    time_t leased_at;
    char *buf = NULL;
    size_t size = 0;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object *messages;
    msgpack_object **pending = NULL;
    msgpack_object **to_ack;
    msgpack_object **to_retry;
    struct flb_in_gcs *ctx = in_context;

    if (flb_input_paused(ins) == FLB_TRUE) {
        return 0;
    }

    if (pubsub_pull(ctx, &buf, &size) != 0 || !buf) {
        return 0;
    }

    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, buf, size, &off) != MSGPACK_UNPACK_SUCCESS) {
        goto done;
    }

    messages = map_lookup(&result.data, "receivedMessages");
    if (!messages || messages->type != MSGPACK_OBJECT_ARRAY ||
        messages->via.array.size == 0) {
        goto done;
    }
    count = messages->via.array.size;

    pending = flb_calloc(count * 3, sizeof(msgpack_object *));
    if (!pending) {
        flb_errno();
        goto done;
    }
    to_ack = pending + count;
    to_retry = pending + count * 2;
    for (i = 0; i < count; i++) {
        pending[i] = map_lookup(&messages->via.array.ptr[i], "ackId");
        if (!pending[i] || pending[i]->type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "pubsub message without ackId");
            goto done;
        }
    }

    leased_at = time(NULL);
    if (ctx->ack_deadline > 0) {
        pubsub_ack(ctx, pending, count, ctx->ack_deadline);
    }

    for (i = 0; i < count; i++) {
        if (flb_input_paused(ins) == FLB_TRUE) {
            /* hand the rest back to Pub/Sub; it redelivers them later */
            for (; i < count; i++) {
                to_retry[n_retry++] = pending[i];
            }
            break;
        }

        /* settle what is done and renew the rest before their leases expire */
        if (ctx->ack_deadline > 0 &&
            time(NULL) - leased_at >= ctx->ack_deadline / 2) {
            if (pubsub_ack(ctx, to_ack, n_ack, -1) == 0) {
                acked += n_ack;
            }
            pubsub_ack(ctx, to_retry, n_retry, 0);
            retried += n_retry;
            n_ack = 0;
            n_retry = 0;
            pubsub_ack(ctx, &pending[i], count - i, ctx->ack_deadline);
            leased_at = time(NULL);
        }

        ret = process_message(ctx, &messages->via.array.ptr[i]);
        if (ret == FLB_IN_GCS_ACK) {
            to_ack[n_ack++] = pending[i];
        }
        else {
            to_retry[n_retry++] = pending[i];
        }
    }

    if (pubsub_ack(ctx, to_ack, n_ack, -1) == 0) {
        acked += n_ack;
    }
    pubsub_ack(ctx, to_retry, n_retry, 0);
    retried += n_retry;

    flb_plg_debug(ctx->ins, "pulled %i notifications: %i acked, %i retried",
                  count, acked, retried);

done:
    flb_free(pending);
    msgpack_unpacked_destroy(&result);
    flb_free(buf);

    return 0;
}

static int load_parsers(struct flb_in_gcs *ctx, struct flb_config *config)
{
    int i = 0;
    struct mk_list *head;
    struct flb_config_map_val *mv;

    if (!ctx->parser_names || mk_list_size(ctx->parser_names) == 0) {
        return 0;
    }

    ctx->parsers = flb_calloc(mk_list_size(ctx->parser_names), sizeof(struct flb_parser *));
    if (!ctx->parsers) {
        flb_errno();
        return -1;
    }

    flb_config_map_foreach(head, mv, ctx->parser_names) {
        ctx->parsers[i] = flb_parser_get(mv->val.str, config);
        if (!ctx->parsers[i]) {
            flb_plg_error(ctx->ins, "parser '%s' not found", mv->val.str);
            return -1;
        }
        i++;
    }
    ctx->parser_count = i;

    return 0;
}

static int resolve_subscription(struct flb_in_gcs *ctx)
{
    const char *project;

    if (strncmp(ctx->subscription, "projects/", 9) == 0) {
        ctx->subscription_path = flb_sds_create(ctx->subscription);
        return ctx->subscription_path ? 0 : -1;
    }

    project = ctx->project_id;
    if (!project) {
        project = ctx->credentials_project_id;
    }
    if (!project) {
        project = getenv("GOOGLE_CLOUD_PROJECT");
    }
    if (!project || project[0] == '\0') {
        flb_plg_error(ctx->ins, "set 'project_id' or use a full subscription "
                      "name (projects/<project>/subscriptions/<name>)");
        return -1;
    }

    ctx->subscription_path = flb_sds_create_size(64);
    if (!ctx->subscription_path) {
        return -1;
    }
    if (!flb_sds_printf(&ctx->subscription_path, "projects/%s/subscriptions/%s",
                        project, ctx->subscription)) {
        return -1;
    }

    return 0;
}

static void in_gcs_destroy(struct flb_in_gcs *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->encoder) {
        flb_log_event_encoder_destroy(ctx->encoder);
    }
    if (ctx->pubsub.u) {
        flb_upstream_destroy(ctx->pubsub.u);
    }
    if (ctx->storage.u) {
        flb_upstream_destroy(ctx->storage.u);
    }
    flb_sds_destroy(ctx->pubsub.base_uri);
    flb_sds_destroy(ctx->storage.base_uri);
    flb_sds_destroy(ctx->subscription_path);
    in_gcs_auth_destroy(ctx);
    flb_free(ctx->parsers);
    flb_free(ctx);
}

static int cb_gcs_init(struct flb_input_instance *ins,
                       struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_gcs *ctx;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_in_gcs));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->config = config;
    ctx->coll_id = -1;

    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    if (!ctx->subscription) {
        flb_plg_error(ins, "'subscription' is required");
        goto error;
    }
    if (ctx->max_messages < 1 || ctx->max_messages > 1000) {
        flb_plg_error(ins, "'max_messages' must be between 1 and 1000");
        goto error;
    }
    if (ctx->ack_deadline != 0 && (ctx->ack_deadline < 10 || ctx->ack_deadline > 600)) {
        flb_plg_error(ins, "'ack_deadline' must be 0 or between 10 and 600 seconds");
        goto error;
    }
    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        ctx->interval_sec = 1;
    }

    if (load_parsers(ctx, config) != 0) {
        goto error;
    }
    if (ctx->object_time_parser_name) {
        ctx->object_time_parser = flb_parser_get(ctx->object_time_parser_name, config);
        if (!ctx->object_time_parser) {
            flb_plg_error(ins, "parser '%s' not found", ctx->object_time_parser_name);
            goto error;
        }
    }
    if (in_gcs_auth_init(ctx, config) != 0) {
        goto error;
    }
    if (resolve_subscription(ctx) != 0) {
        goto error;
    }
    if (endpoint_init(ctx, config, ctx->pubsub_endpoint, &ctx->pubsub) != 0 ||
        endpoint_init(ctx, config, ctx->storage_endpoint, &ctx->storage) != 0) {
        goto error;
    }

    ctx->encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!ctx->encoder) {
        flb_plg_error(ins, "cannot create the log event encoder");
        goto error;
    }

    flb_input_set_context(ins, ctx);

    ret = flb_input_set_collector_time(ins, cb_gcs_collect, ctx->interval_sec,
                                       ctx->interval_nsec, config);
    if (ret == -1) {
        flb_plg_error(ins, "cannot create the collector");
        goto error;
    }
    ctx->coll_id = ret;

    flb_plg_info(ins, "pulling %s", ctx->subscription_path);

    return 0;

error:
    flb_input_set_context(ins, NULL);
    in_gcs_destroy(ctx);
    return -1;
}

static void cb_gcs_pause(void *data, struct flb_config *config)
{
    struct flb_in_gcs *ctx = data;

    flb_input_collector_pause(ctx->coll_id, ctx->ins);
}

static void cb_gcs_resume(void *data, struct flb_config *config)
{
    struct flb_in_gcs *ctx = data;

    flb_input_collector_resume(ctx->coll_id, ctx->ins);
}

static int cb_gcs_exit(void *data, struct flb_config *config)
{
    in_gcs_destroy(data);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "subscription", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, subscription),
     "Pub/Sub subscription that receives the bucket OBJECT_FINALIZE "
     "notifications: 'projects/<project>/subscriptions/<name>' or '<name>'."
    },
    {
     FLB_CONFIG_MAP_STR, "project_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, project_id),
     "Project of a short subscription name. Defaults to the credentials "
     "project or GOOGLE_CLOUD_PROJECT."
    },
    {
     FLB_CONFIG_MAP_STR, "google_service_credentials", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, credentials_file),
     "Service account key file. Defaults to GOOGLE_APPLICATION_CREDENTIALS, "
     "then the metadata server."
    },
    {
     FLB_CONFIG_MAP_STR, "metadata_server", FLB_IN_GCS_METADATA_SERVER,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, metadata_server),
     "Metadata server used when no credentials file is set."
    },
    {
     FLB_CONFIG_MAP_STR, "auth", "auto",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, auth),
     "'auto' to authenticate, or 'none' for the Pub/Sub and GCS emulators."
    },
    {
     FLB_CONFIG_MAP_STR, "pubsub_endpoint", FLB_IN_GCS_PUBSUB_ENDPOINT,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, pubsub_endpoint),
     "Pub/Sub API endpoint."
    },
    {
     FLB_CONFIG_MAP_STR, "storage_endpoint", FLB_IN_GCS_STORAGE_ENDPOINT,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, storage_endpoint),
     "Cloud Storage API endpoint."
    },
    {
     FLB_CONFIG_MAP_INT, "max_messages", "10",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, max_messages),
     "Maximum notifications per pull (1-1000)."
    },
    {
     FLB_CONFIG_MAP_INT, "ack_deadline", "0",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, ack_deadline),
     "If set (10-600), extend the ack deadline of every pulled batch to this "
     "many seconds. 0 keeps the subscription default."
    },
    {
     FLB_CONFIG_MAP_INT, "interval_sec", "1",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, interval_sec),
     "Seconds between pulls."
    },
    {
     FLB_CONFIG_MAP_INT, "interval_nsec", "0",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, interval_nsec),
     "Nanoseconds between pulls."
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", "64M",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, buffer_max_size),
     "Largest object, after decompression, that is read. Larger objects are "
     "skipped with an error."
    },
    {
     FLB_CONFIG_MAP_STR, "parser", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_in_gcs, parser_names),
     "Parser for each line; may be set more than once, the first that "
     "matches wins. A line with no parsed time keeps the previous line's time."
    },
    {
     FLB_CONFIG_MAP_STR, "object_time_parser", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, object_time_parser_name),
     "Parser applied to the object name, e.g. to 'dt=YYYY-MM-DD/hour=HH'. Its "
     "time is used for lines before the first timestamped line of an object. "
     "Without it, or when it does not match, the notification's eventTime is used."
    },
    {
     FLB_CONFIG_MAP_BOOL, "raw_line", "false",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, raw_line),
     "Use parsers only for the timestamp and keep the unparsed line under 'key'."
    },
    {
     FLB_CONFIG_MAP_STR, "key", "log",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, key),
     "Key that holds the line when it is not parsed."
    },
    {
     FLB_CONFIG_MAP_STR, "object_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, object_key),
     "If set, add the object name to every record under this key."
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_gcs_plugin = {
    .name         = "gcs",
    .description  = "Google Cloud Storage objects via Pub/Sub notifications",
    .cb_init      = cb_gcs_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_gcs_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_gcs_pause,
    .cb_resume    = cb_gcs_resume,
    .cb_exit      = cb_gcs_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_THREADED | FLB_IO_TLS
};
