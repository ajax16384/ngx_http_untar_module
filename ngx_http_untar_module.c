/*
 * Copyright (C) 2019 Andrei Kurushin
 * For conditions of distribution and use, see copyright notice in LICENSE
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_http_untar(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
    ngx_rbtree_t                     archives_rbtree;
    ngx_rbtree_node_t                archives_sentinel;
    ngx_pool_t                       *archives_pool;
} ngx_http_untar_main_conf_t;

typedef struct {
    ngx_http_complex_value_t    *file_name;
    ngx_http_complex_value_t    *archive_name;
} ngx_http_untar_loc_conf_t;

// must be packed
typedef struct {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
} tar_header_t;

typedef struct {
    ngx_str_node_t              str_node;
    ngx_str_t                   file_name;
    off_t                       file_size;
    off_t                       offset;
    time_t                      mtime;
} untar_archive_item_t;

typedef struct {
    ngx_str_node_t              str_node;
    ngx_str_t                   file_name;
    off_t                       file_size;
    time_t                      mtime;
    ngx_int_t                   valid;
    ngx_pool_t                  *items_pool;
    ngx_rbtree_t                items_rbtree;
    ngx_rbtree_node_t           items_sentinel;
} untar_archive_t;

static ngx_command_t ngx_http_untar_commands[] = {
    {
      ngx_string("untar"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_untar,
      0,
      0,
      NULL
    }, {
      ngx_string("untar_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_untar_loc_conf_t, file_name),
      NULL
    }, {
      ngx_string("untar_archive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_untar_loc_conf_t, archive_name),
      NULL
    },
    ngx_null_command
};

static void *
ngx_http_untar_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_untar_main_conf_t  *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_untar_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    ngx_rbtree_init(&mcf->archives_rbtree, &mcf->archives_sentinel,
                    ngx_str_rbtree_insert_value);
    mcf->archives_pool = cf->pool;

    return mcf;
}

static void *
ngx_http_untar_create_loc_conf(ngx_conf_t *cf) {

    ngx_http_untar_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_untar_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *
ngx_http_untar_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {

    ngx_http_untar_loc_conf_t *prev = parent;
    ngx_http_untar_loc_conf_t *conf = child;

    if (conf->file_name == NULL) {
        conf->file_name = prev->file_name;
    }

    if (conf->archive_name == NULL) {
        conf->archive_name = prev->archive_name;
    }

    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_untar_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    ngx_http_untar_create_main_conf,        /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_untar_create_loc_conf,         /* create location configuration */
    ngx_http_untar_merge_loc_conf           /* merge location configuration */
};


ngx_module_t ngx_http_untar_module = {
    NGX_MODULE_V1,
    &ngx_http_untar_module_ctx,             /* module context */
    ngx_http_untar_commands,                /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
copy_zero_term_string(ngx_http_request_t *r, ngx_str_t *to, ngx_str_t *from)
{
    to->len = from->len;
    to->data = ngx_pnalloc(r->pool, from->len + 1);
    if (to->data == NULL) {
        return NGX_ERROR;
    }
    to->data[to->len] = '\0';
    ngx_memcpy(to->data, from->data, from->len);
    return NGX_OK;
}


static ngx_int_t
octal_to_int(const char *src, size_t size, uint64_t *out_res)
{
    char            c;
    size_t          i;
    uint64_t        res = 0;
    for (i = size; i != 0; --i, ++src) {
        c = *src;
        if (c == ' ') {
            continue;
        }
        if (c == '\0') {
            break;
        }
        if (c < '0' || c > '7') {
            return NGX_ERROR;
        }
        res <<= 3;
        res |= (uint64_t)(c - '0');
    }
    *out_res = res;
    return NGX_OK;
}


static ngx_int_t
is_last_tar_header(const u_char *buf)
{
    size_t          i;
    for (i = 0; i < sizeof(tar_header_t); ++i) {
        if (buf[i] != 0) {
            return NGX_DECLINED;
        }
    }
    return NGX_OK;
}


static untar_archive_t *
get_untar_archive(ngx_http_request_t *r,
                  ngx_open_file_info_t *ofi, ngx_str_t *archive_name)
{
    char                        *lfn_buf;
    char                        *current_lfn;
    char                        *current_item_name;
    off_t                       current_offset;
    off_t                       pad_size;
    ssize_t                     read_size;
    uint32_t                    archive_hash;
    uint32_t                    archive_item_hash;
    uint64_t                    current_file_size;
    uint64_t                    current_mtime;
    ngx_log_t                   *log;
    ngx_int_t                   has_last_tar_header;
    ngx_file_t                  file;
    tar_header_t                tar_header;
    untar_archive_t             *archive;
    untar_archive_item_t        *archive_item;
    ngx_http_untar_main_conf_t  *mcf;

    log = r->connection->log;

    if (sizeof(tar_header) != 512) {
        return NULL;
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_untar_module);

    archive_hash = ngx_crc32_long(archive_name->data, archive_name->len);

    archive = (untar_archive_t *)ngx_str_rbtree_lookup(
                            &mcf->archives_rbtree,archive_name,
                            archive_hash);

    if (archive != NULL) {
        if ((archive->file_size == ofi->size)
            && (archive->mtime == ofi->mtime)) {

            if (archive->valid != NGX_OK) {
                return NULL;
            }
            return archive;
        }
        ngx_rbtree_init(&archive->items_rbtree,
                        &archive->items_sentinel,
                        ngx_str_rbtree_insert_value);
        ngx_reset_pool(archive->items_pool);
    }
    else {
        archive = ngx_pcalloc(mcf->archives_pool, sizeof(untar_archive_t));
        if (archive == NULL) {
            return NULL;
        }
        archive->items_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE,
                                              mcf->archives_pool->log);
        if (archive->items_pool == NULL) {
            return NULL;
        }

        ngx_rbtree_init(&archive->items_rbtree,
                        &archive->items_sentinel,
                        ngx_str_rbtree_insert_value);

        archive->file_name.len = archive_name->len;
        archive->file_name.data = ngx_pstrdup(mcf->archives_pool, archive_name);
        if (archive->file_name.data == NULL) {
            return NULL;
        }

        archive->str_node.node.key = archive_hash;
        archive->str_node.str = archive->file_name;

        ngx_rbtree_insert(&mcf->archives_rbtree, &archive->str_node.node);
    }

    archive->valid = NGX_ERROR;
    archive->file_size = ofi->size;
    archive->mtime = ofi->mtime;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = *archive_name;
    file.log = log;
    file.fd = ofi->fd;

    current_offset = 0;
    has_last_tar_header = NGX_ERROR;
    lfn_buf = NULL;
    current_lfn = NULL;

    while (current_offset < ofi->size) {
        read_size = ngx_read_file(&file,
                                  (u_char *)&tar_header,
                                  sizeof(tar_header),
                                  current_offset);
        if (read_size != sizeof(tar_header)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "Unable to read tar header \"%s\".", archive_name->data);
            return NULL;
        }

        if (is_last_tar_header((u_char *)&tar_header) == NGX_OK) {
            has_last_tar_header = NGX_OK;
            break;
        }

        // force tar_header.name to be zero termination string
        // "mode" must be parsed before this line
        tar_header.mode[0] = '\0';

        if (octal_to_int(tar_header.size,
                         sizeof(tar_header.size),
                         &current_file_size) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "Wrong tar header item size \"%s\" \"%s\".",
                archive_name->data, tar_header.name);
            return NULL;
        }

        if (current_file_size >= NGX_MAX_OFF_T_VALUE) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "Wrong tar header item size value \"%s\" \"%s\".",
                archive_name->data, tar_header.name);
            return NULL;
        }

        if (octal_to_int(tar_header.mtime,
                         sizeof(tar_header.mtime),
                         &current_mtime) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "Wrong tar header item mtime \"%s\" \"%s\".",
                archive_name->data, tar_header.name);
            return NULL;
        }

        if ((tar_header.typeflag == '0') || (tar_header.typeflag == '\0')) {

            if ((current_mtime >= NGX_MAX_TIME_T_VALUE) || (current_mtime <= 0)) {
                current_mtime = ofi->mtime;
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "Tar item contains wrong mtime, using archive mtime \"%s\" \"%s\".",
                    archive_name->data, tar_header.name);
            }

            archive_item = ngx_pcalloc(archive->items_pool,
                                       sizeof(untar_archive_item_t));

            if (archive_item == NULL) {
                return NULL;
            }

            archive_item->file_size = current_file_size;
            archive_item->mtime = current_mtime;

            if (current_lfn != NULL) {
                current_item_name = current_lfn;
                current_lfn = NULL;
            } else {
                current_item_name = tar_header.name;
            }
            archive_item->file_name.len = ngx_strlen(current_item_name);
            archive_item->file_name.data = ngx_pnalloc(archive->items_pool,
                                                       archive_item->file_name.len);
            if (archive_item->file_name.data == NULL) {
                return NULL;
            }

            ngx_memcpy(archive_item->file_name.data,
                       current_item_name,
                       archive_item->file_name.len);

            archive_item_hash = ngx_crc32_long(archive_item->file_name.data,
                                               archive_item->file_name.len);
            archive_item->str_node.node.key = archive_item_hash;
            archive_item->str_node.str = archive_item->file_name;

            ngx_rbtree_insert(&archive->items_rbtree,
                              &archive_item->str_node.node);
        } else {
            archive_item = NULL;
            current_lfn = NULL;
            if (tar_header.typeflag == 'L') {
                if ((current_file_size > NGX_MAX_PATH + 1) || (current_file_size <= 0)) {
                    ngx_log_error(NGX_LOG_WARN, log, 0,
                        "Tar long file name item contains invalid data \"%s\".",
                        archive_name->data);
                } else {
                    if (lfn_buf == NULL) {
                        lfn_buf = ngx_pnalloc(archive->items_pool, NGX_MAX_PATH + 2);
                        if (lfn_buf == NULL) {
                            return NULL;
                        }
                    }
                    current_lfn = lfn_buf;
                    current_lfn[current_file_size] = '\0';
                    read_size = ngx_read_file(&file,
                        (u_char*)current_lfn,
                        current_file_size,
                        current_offset + sizeof(tar_header));
                    if (read_size != ((ssize_t) current_file_size)) {
                        ngx_log_error(NGX_LOG_ERR, log, 0,
                            "Unable to read long file name data \"%s\".", archive_name->data);
                        return NULL;
                    }
                }
            }
        }

        current_offset += sizeof(tar_header);
        if (archive_item != NULL) {
            archive_item->offset = current_offset;
        }
        current_offset += current_file_size;

        pad_size = current_file_size % sizeof(tar_header_t);
        if (pad_size != 0) {
            current_offset += (sizeof(tar_header_t) - pad_size);
        }
    }

    if (has_last_tar_header != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "Has no last tar header \"%s\".", archive_name->data);
        return NULL;
    }

    archive->valid = NGX_OK;
    return archive;
}

static ngx_int_t
ngx_http_untar_handler(ngx_http_request_t *r)
{
    uint32_t                    archive_item_hash;
    ngx_str_t                   file_name_conf;
    ngx_str_t                   archive_name_conf;
    ngx_str_t                   file_name;
    ngx_str_t                   archive_name;
    ngx_log_t                   *log;
    ngx_int_t                   rc;
    ngx_buf_t                   *b;
    ngx_uint_t                  level;
    ngx_chain_t                 out;
    untar_archive_t             *archive;
    ngx_open_file_info_t        of;
    untar_archive_item_t        *archive_item;
    ngx_http_core_loc_conf_t    *clcf;

    log = r->connection->log;
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_http_untar_loc_conf_t *lcf;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_untar_module);

    if (ngx_http_complex_value(r,
            lcf->file_name, &file_name_conf) != NGX_OK
        || ngx_http_complex_value(r,
            lcf->archive_name, &archive_name_conf) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "Failed to read untar module configuration settings.");
        return NGX_ERROR;
    }

    rc = copy_zero_term_string(r, &file_name, &file_name_conf);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = copy_zero_term_string(r, &archive_name, &archive_name_conf);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http tar archive: \"%V\" file: \"%V\"",
                   &archive_name, &file_name);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &archive_name, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &archive_name, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, archive_name.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", archive_name.data);
        }

        return NGX_DECLINED;
    }


    archive = get_untar_archive(r, &of, &archive_name);

    if (archive == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    archive_item_hash = ngx_crc32_long(file_name.data, file_name.len);

    archive_item = (untar_archive_item_t *)ngx_str_rbtree_lookup(
                                            &archive->items_rbtree,
                                            &file_name,
                                            archive_item_hash);

    if (archive_item == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "File not found \"%s\" \"%s\".",
            archive_name.data, file_name.data);
        return NGX_HTTP_NOT_FOUND;
    }

    r->root_tested = !r->error_page;


    log->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = archive_item->file_size;
    r->headers_out.last_modified_time = archive_item->mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }


    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->allow_ranges = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = archive_item->offset;
    b->file_last = (archive_item->offset + archive_item->file_size);

    b->in_file = b->file_last ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = file_name;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static char *
ngx_http_untar(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_untar_handler;

    return NGX_CONF_OK;
}

