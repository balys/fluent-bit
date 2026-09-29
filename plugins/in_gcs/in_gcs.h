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

#ifndef FLB_IN_GCS_H
#define FLB_IN_GCS_H

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>

#define FLB_IN_GCS_PUBSUB_ENDPOINT   "https://pubsub.googleapis.com"
#define FLB_IN_GCS_STORAGE_ENDPOINT  "https://storage.googleapis.com"
#define FLB_IN_GCS_METADATA_SERVER   "http://metadata.google.internal"
#define FLB_IN_GCS_AUTH_URL          "https://oauth2.googleapis.com/token"
#define FLB_IN_GCS_SCOPE             "https://www.googleapis.com/auth/pubsub " \
                                     "https://www.googleapis.com/auth/devstorage.read_only"
#define FLB_IN_GCS_METADATA_TOKEN_URI \
    "/computeMetadata/v1/instance/service-accounts/default/token"
#define FLB_IN_GCS_TOKEN_LIFETIME    3000
#define FLB_IN_GCS_API_BUFFER_MAX    (4 * 1024 * 1024)
#define FLB_IN_GCS_APPEND_SIZE       (1024 * 1024)

/* result of processing one notification */
#define FLB_IN_GCS_ACK    0
#define FLB_IN_GCS_RETRY  1

struct flb_in_gcs_endpoint {
    flb_sds_t base_uri;             /* path prefix, without trailing slash */
    struct flb_upstream *u;
};

struct flb_in_gcs {
    /* configuration */
    flb_sds_t subscription;
    flb_sds_t project_id;
    flb_sds_t pubsub_endpoint;
    flb_sds_t storage_endpoint;
    flb_sds_t credentials_file;
    flb_sds_t metadata_server;
    flb_sds_t auth;
    flb_sds_t key;
    flb_sds_t object_key;
    int max_messages;
    int ack_deadline;
    int interval_sec;
    int interval_nsec;
    int raw_line;
    size_t buffer_max_size;
    struct mk_list *parser_names;
    flb_sds_t object_time_parser_name;

    /* runtime */
    flb_sds_t subscription_path;    /* projects/<p>/subscriptions/<s> */
    struct flb_parser **parsers;
    int parser_count;
    struct flb_parser *object_time_parser;
    int coll_id;
    struct flb_in_gcs_endpoint pubsub;
    struct flb_in_gcs_endpoint storage;
    struct flb_log_event_encoder *encoder;

    /* authentication */
    int auth_none;
    int auth_metadata;
    flb_sds_t client_email;
    flb_sds_t private_key;
    flb_sds_t credentials_project_id;
    struct flb_oauth2 *oauth2;
    struct flb_upstream *metadata_u;

    struct flb_input_instance *ins;
    struct flb_config *config;
};

/* in_gcs_auth.c */
int in_gcs_auth_init(struct flb_in_gcs *ctx, struct flb_config *config);
int in_gcs_auth_header(struct flb_in_gcs *ctx, flb_sds_t *out_header);
void in_gcs_auth_invalidate(struct flb_in_gcs *ctx);
void in_gcs_auth_destroy(struct flb_in_gcs *ctx);

#endif
