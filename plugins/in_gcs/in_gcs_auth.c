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
 * Google authentication for in_gcs: a service account key file (JWT bearer
 * grant) or the GCE/GKE metadata server. 'auth none' disables it, which is
 * what the Pub/Sub and GCS emulators expect.
 */

#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_pack.h>

#include <msgpack.h>
#include <string.h>
#include <time.h>

#include "in_gcs.h"

static flb_sds_t map_get_str(msgpack_object *map, const char *key)
{
    size_t i;
    size_t key_len;
    msgpack_object *k;
    msgpack_object *v;

    key_len = strlen(key);
    for (i = 0; i < map->via.map.size; i++) {
        k = &map->via.map.ptr[i].key;
        v = &map->via.map.ptr[i].val;
        if (k->type == MSGPACK_OBJECT_STR && k->via.str.size == key_len &&
            strncmp(k->via.str.ptr, key, key_len) == 0 &&
            v->type == MSGPACK_OBJECT_STR) {
            return flb_sds_create_len(v->via.str.ptr, v->via.str.size);
        }
    }

    return NULL;
}

static int read_credentials_file(struct flb_in_gcs *ctx, const char *path)
{
    int ret;
    int root_type;
    char *buf = NULL;
    size_t size;
    size_t consumed;
    size_t off = 0;
    flb_sds_t json;
    flb_sds_t type = NULL;
    msgpack_unpacked result;

    json = flb_file_read(path);
    if (!json) {
        flb_plg_error(ctx->ins, "cannot read credentials file '%s'", path);
        return -1;
    }

    ret = flb_pack_json(json, flb_sds_len(json), &buf, &size, &root_type, &consumed);
    flb_sds_destroy(json);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "invalid JSON in credentials file '%s'", path);
        return -1;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS || result.data.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "credentials file '%s' is not a JSON object", path);
        msgpack_unpacked_destroy(&result);
        flb_free(buf);
        return -1;
    }

    type = map_get_str(&result.data, "type");
    ctx->client_email = map_get_str(&result.data, "client_email");
    ctx->private_key = map_get_str(&result.data, "private_key");
    ctx->credentials_project_id = map_get_str(&result.data, "project_id");
    msgpack_unpacked_destroy(&result);
    flb_free(buf);

    if (type && strcmp(type, "service_account") != 0) {
        flb_plg_error(ctx->ins, "credentials type '%s' is not supported, "
                      "use a service account key or the metadata server", type);
        flb_sds_destroy(type);
        return -1;
    }
    flb_sds_destroy(type);

    if (!ctx->client_email || !ctx->private_key) {
        flb_plg_error(ctx->ins, "credentials file '%s' has no client_email "
                      "or private_key", path);
        return -1;
    }

    return 0;
}

static int base64_url_encode(unsigned char *out, size_t out_size,
                             const unsigned char *in, size_t in_size, size_t *out_len)
{
    size_t i;
    size_t len;

    if (flb_base64_encode(out, out_size, &len, in, in_size) != 0) {
        return -1;
    }

    for (i = 0; i < len && out[i] != '='; i++) {
        if (out[i] == '+') {
            out[i] = '-';
        }
        else if (out[i] == '/') {
            out[i] = '_';
        }
    }
    out[i] = '\0';
    *out_len = i;

    return 0;
}

/* Build a signed RS256 JWT: base64url(header).base64url(claims).base64url(sig) */
static flb_sds_t jwt_create(struct flb_in_gcs *ctx, const char *claims)
{
    int ret;
    size_t len;
    size_t buf_size;
    size_t sig_len;
    unsigned char *buf;
    unsigned char digest[32];
    unsigned char sig[512];
    const char *header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    flb_sds_t jwt;
    flb_sds_t tmp;

    buf_size = ((strlen(claims) + 2) / 3) * 4 + 1;
    if (buf_size < ((sizeof(sig) + 2) / 3) * 4 + 1) {
        buf_size = ((sizeof(sig) + 2) / 3) * 4 + 1;
    }
    buf = flb_malloc(buf_size);
    if (!buf) {
        flb_errno();
        return NULL;
    }

    jwt = flb_sds_create_size(1024);
    if (!jwt) {
        flb_free(buf);
        return NULL;
    }

    ret = base64_url_encode(buf, buf_size, (unsigned char *) header, strlen(header), &len);
    if (ret == 0) {
        tmp = flb_sds_cat(jwt, (char *) buf, len);
        ret = tmp ? 0 : -1;
        jwt = tmp ? tmp : jwt;
    }
    if (ret == 0) {
        tmp = flb_sds_cat(jwt, ".", 1);
        ret = tmp ? 0 : -1;
        jwt = tmp ? tmp : jwt;
    }
    if (ret == 0) {
        ret = base64_url_encode(buf, buf_size, (unsigned char *) claims, strlen(claims), &len);
    }
    if (ret == 0) {
        tmp = flb_sds_cat(jwt, (char *) buf, len);
        ret = tmp ? 0 : -1;
        jwt = tmp ? tmp : jwt;
    }
    if (ret == 0) {
        ret = flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) jwt, flb_sds_len(jwt),
                              digest, sizeof(digest));
        ret = (ret == FLB_CRYPTO_SUCCESS) ? 0 : -1;
    }
    if (ret == 0) {
        sig_len = sizeof(sig);
        ret = flb_crypto_sign_simple(FLB_CRYPTO_PRIVATE_KEY, FLB_CRYPTO_PADDING_PKCS1,
                                     FLB_HASH_SHA256, (unsigned char *) ctx->private_key,
                                     flb_sds_len(ctx->private_key) + 1,
                                     digest, sizeof(digest), sig, &sig_len);
        ret = (ret == FLB_CRYPTO_SUCCESS) ? 0 : -1;
    }
    if (ret == 0) {
        ret = base64_url_encode(buf, buf_size, sig, sig_len, &len);
    }
    if (ret == 0) {
        tmp = flb_sds_cat(jwt, ".", 1);
        ret = tmp ? 0 : -1;
        jwt = tmp ? tmp : jwt;
    }
    if (ret == 0) {
        tmp = flb_sds_cat(jwt, (char *) buf, len);
        ret = tmp ? 0 : -1;
        jwt = tmp ? tmp : jwt;
    }

    flb_free(buf);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not sign the service account JWT");
        flb_sds_destroy(jwt);
        return NULL;
    }

    return jwt;
}

static int token_from_service_account(struct flb_in_gcs *ctx)
{
    int ret;
    time_t now;
    char claims[1024];
    flb_sds_t jwt;

    now = time(NULL);
    ret = snprintf(claims, sizeof(claims),
                   "{\"iss\":\"%s\",\"scope\":\"%s\",\"aud\":\"%s\","
                   "\"exp\":%llu,\"iat\":%llu}",
                   ctx->client_email, FLB_IN_GCS_SCOPE, FLB_IN_GCS_AUTH_URL,
                   (unsigned long long) (now + FLB_IN_GCS_TOKEN_LIFETIME),
                   (unsigned long long) now);
    if (ret < 0 || (size_t) ret >= sizeof(claims)) {
        return -1;
    }

    jwt = jwt_create(ctx, claims);
    if (!jwt) {
        return -1;
    }

    flb_oauth2_payload_clear(ctx->oauth2);
    ret = flb_oauth2_payload_append(ctx->oauth2, "grant_type", -1,
                                    "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
                                    -1);
    if (ret == 0) {
        ret = flb_oauth2_payload_append(ctx->oauth2, "assertion", -1,
                                        jwt, flb_sds_len(jwt));
    }
    flb_sds_destroy(jwt);

    if (ret != 0 || !flb_oauth2_token_get(ctx->oauth2)) {
        flb_plg_error(ctx->ins, "could not get an access token for '%s'",
                      ctx->client_email);
        return -1;
    }

    return 0;
}

static int token_from_metadata_server(struct flb_in_gcs *ctx)
{
    int ret;
    size_t bytes_sent;
    struct flb_connection *conn;
    struct flb_http_client *c;

    conn = flb_upstream_conn_get(ctx->metadata_u);
    if (!conn) {
        flb_plg_error(ctx->ins, "cannot connect to the metadata server '%s'; set "
                      "'google_service_credentials' when not running on GCE/GKE",
                      ctx->metadata_server);
        return -1;
    }

    c = flb_http_client(conn, FLB_HTTP_GET, FLB_IN_GCS_METADATA_TOKEN_URI,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_upstream_conn_release(conn);
        return -1;
    }
    flb_http_buffer_size(c, 16384);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Metadata-Flavor", 15, "Google", 6);

    ret = flb_http_do(c, &bytes_sent);
    if (ret == 0 && c->resp.status == 200) {
        ret = flb_oauth2_parse_json_response(c->resp.payload, c->resp.payload_size,
                                             ctx->oauth2);
    }
    else {
        flb_plg_error(ctx->ins, "metadata server token request failed: status=%i",
                      ret == 0 ? c->resp.status : -1);
        ret = -1;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(conn);

    return ret;
}

int in_gcs_auth_init(struct flb_in_gcs *ctx, struct flb_config *config)
{
    const char *env;

    if (strcasecmp(ctx->auth, "none") == 0) {
        ctx->auth_none = FLB_TRUE;
        flb_plg_info(ctx->ins, "authentication disabled ('auth none')");
        return 0;
    }
    if (strcasecmp(ctx->auth, "auto") != 0) {
        flb_plg_error(ctx->ins, "invalid 'auth' value '%s', use 'auto' or 'none'",
                      ctx->auth);
        return -1;
    }

    if (!ctx->credentials_file) {
        env = getenv("GOOGLE_APPLICATION_CREDENTIALS");
        if (env && env[0] != '\0') {
            ctx->credentials_file = flb_sds_create(env);
            if (!ctx->credentials_file) {
                return -1;
            }
        }
    }

    if (ctx->credentials_file) {
        if (read_credentials_file(ctx, ctx->credentials_file) != 0) {
            return -1;
        }
        flb_plg_info(ctx->ins, "using service account '%s'", ctx->client_email);
    }
    else {
        ctx->auth_metadata = FLB_TRUE;
        ctx->metadata_u = flb_upstream_create_url(config, ctx->metadata_server,
                                                  FLB_IO_TCP, NULL);
        if (!ctx->metadata_u) {
            flb_plg_error(ctx->ins, "invalid 'metadata_server' '%s'", ctx->metadata_server);
            return -1;
        }
        flb_stream_disable_async_mode(&ctx->metadata_u->base);
        flb_input_upstream_set(ctx->metadata_u, ctx->ins);
        flb_plg_info(ctx->ins, "using the metadata server for authentication");
    }

    ctx->oauth2 = flb_oauth2_create(config, FLB_IN_GCS_AUTH_URL, FLB_IN_GCS_TOKEN_LIFETIME);
    if (!ctx->oauth2) {
        flb_plg_error(ctx->ins, "cannot create the OAuth2 context");
        return -1;
    }
    flb_input_upstream_set(ctx->oauth2->u, ctx->ins);

    return 0;
}

int in_gcs_auth_header(struct flb_in_gcs *ctx, flb_sds_t *out_header)
{
    int ret = 0;
    flb_sds_t header;

    *out_header = NULL;
    if (ctx->auth_none) {
        return 0;
    }

    if (flb_oauth2_token_expired(ctx->oauth2) == FLB_TRUE) {
        if (ctx->auth_metadata) {
            ret = token_from_metadata_server(ctx);
        }
        else {
            ret = token_from_service_account(ctx);
        }
    }
    if (ret != 0 || !ctx->oauth2->access_token) {
        return -1;
    }

    header = flb_sds_create_size(flb_sds_len(ctx->oauth2->access_token) + 16);
    if (!header) {
        return -1;
    }
    if (!flb_sds_printf(&header, "Bearer %s", ctx->oauth2->access_token)) {
        flb_sds_destroy(header);
        return -1;
    }
    *out_header = header;

    return 0;
}

void in_gcs_auth_invalidate(struct flb_in_gcs *ctx)
{
    if (ctx->oauth2) {
        flb_oauth2_invalidate_token(ctx->oauth2);
    }
}

void in_gcs_auth_destroy(struct flb_in_gcs *ctx)
{
    if (ctx->oauth2) {
        flb_oauth2_destroy(ctx->oauth2);
        ctx->oauth2 = NULL;
    }
    if (ctx->metadata_u) {
        flb_upstream_destroy(ctx->metadata_u);
        ctx->metadata_u = NULL;
    }
    flb_sds_destroy(ctx->client_email);
    flb_sds_destroy(ctx->private_key);
    flb_sds_destroy(ctx->credentials_project_id);
    ctx->client_email = NULL;
    ctx->private_key = NULL;
    ctx->credentials_project_id = NULL;
}
