#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_http_demo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_demo_handler(ngx_http_request_t *r);
static char* ngx_http_demo_arg_strscript(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http_demo_arg_compilecomplexvalue(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_demo_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_demo_upstream_handler(ngx_http_request_t *r);
static ngx_int_t demo_upstream_create_request(ngx_http_request_t *r);
static ngx_int_t demo_upstream_process_status_line(ngx_http_request_t *r);
static void demo_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static void* ngx_http_demo_create_loc_conf(ngx_conf_t *cf);

static char* ngx_http_demo_merge_loc_conf(ngx_conf_t *cf,
            void *parent, void *child);

static ngx_conf_enum_t  ngx_http_demo_enum[] = {
    { ngx_string("open"), 1 },
    { ngx_string("close"), 2 },
    { ngx_null_string, 0 }
};

#define NGX_http_demo_BIT1  0x0001
#define NGX_http_demo_BIT2  0x0002
#define NGX_http_demo_BIT3  0x0004
static ngx_conf_bitmask_t  ngx_http_demo_bitmask[] = {
    { ngx_string("bit1"), NGX_http_demo_BIT1 },
    { ngx_string("bit2"), NGX_http_demo_BIT2 },
    { ngx_string("bit3"), NGX_http_demo_BIT3 },
    { ngx_null_string, 0 }
};

typedef struct {
    ngx_http_status_t status;
} ngx_http_demo_ctx_t;

typedef struct {
    ngx_flag_t arg_flag;
    ngx_str_t arg_str;
    ngx_array_t *arg_str_array;
    ngx_array_t *arg_keyval;
    ngx_uint_t arg_num;
    size_t arg_size;
    off_t arg_off;
    ngx_msec_t arg_msec;
    time_t arg_sec;
    ngx_bufs_t arg_bufs;
    ngx_uint_t arg_enum;
    ngx_uint_t arg_bitmask;

    ngx_array_t *arg_strscript_lengths;
    ngx_array_t *arg_strscript_values;
	ngx_str_t arg_strscript;

    ngx_http_complex_value_t *arg_compilecomplexvalue;
    ngx_str_t arg_compilecomplexvalue_str;

    ngx_http_upstream_conf_t upstreamconf;

} ngx_http_demo_loc_conf_t;

static ngx_command_t ngx_http_demo_commands[] = {
    { ngx_string("demo"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
    ngx_http_demo,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

    { ngx_string("demo_upstream"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
    ngx_http_demo_upstream,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

    { ngx_string("demo_arg_flag"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_flag),
    NULL },

    { ngx_string("demo_arg_str"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_str),
    NULL },

    { ngx_string("demo_arg_str_array"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_array_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_str_array),
    NULL },

    { ngx_string("demo_arg_keyval"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
    ngx_conf_set_keyval_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_keyval),
    NULL },

    { ngx_string("demo_arg_num"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_num),
    NULL },

    { ngx_string("demo_arg_size"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_size),
    NULL },

    { ngx_string("demo_arg_off"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_off_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_off),
    NULL },

    { ngx_string("demo_arg_msec"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_msec),
    NULL },

    { ngx_string("demo_arg_sec"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_sec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_sec),
    NULL },

    { ngx_string("demo_arg_bufs"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
    ngx_conf_set_bufs_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_bufs),
    NULL },

    { ngx_string("demo_arg_enum"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_bufs_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_enum),
    &ngx_http_demo_enum},

    { ngx_string("demo_arg_bitmask"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_bitmask_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, arg_bitmask),
    &ngx_http_demo_bitmask},

    { ngx_string("demo_arg_strscript"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_http_demo_arg_strscript,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

    { ngx_string("demo_arg_compilecomplexvalue"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_http_demo_arg_compilecomplexvalue,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

    { ngx_string("demo_ups_connect_timeout"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_demo_loc_conf_t, upstreamconf.connect_timeout),
    //offsetof(ngx_http_demo_loc_conf_t, arg_msec),
    NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_demo_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_demo_create_loc_conf,
    ngx_http_demo_merge_loc_conf
};

ngx_module_t ngx_http_demo_module = {
    NGX_MODULE_V1,
    &ngx_http_demo_module_ctx,
    ngx_http_demo_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_demo_arg_strscript_eval(ngx_http_request_t *r, ngx_http_demo_loc_conf_t *dlcf);

static char *ngx_http_demo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_demo_handler;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_demo_handler(ngx_http_request_t *r) {
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_http_demo_loc_conf_t *democf;
    democf = ngx_http_get_module_loc_conf(r, ngx_http_demo_module);

    ngx_str_t type = ngx_string("text/plain");

    u_char buffer_strarray[1000];
    ngx_memset(buffer_strarray, 0, sizeof(buffer_strarray));
    ngx_str_t* tmp;
    for (ngx_uint_t i=0; i<democf->arg_str_array->nelts; i++) {
        tmp = democf->arg_str_array->elts;
        ngx_sprintf(buffer_strarray, "%s\n\t%s", buffer_strarray, (char*)tmp[i].data);
    }

    u_char buffer_keyval[1000];
    ngx_keyval_t* tmpkv;
    ngx_memset(buffer_keyval, 0, sizeof(buffer_keyval));
    for (ngx_uint_t i=0; i<democf->arg_keyval->nelts; i++) {
        tmpkv = democf->arg_keyval->elts;
        ngx_sprintf(buffer_keyval, "%s\n\tkey:%s, val:%s", buffer_keyval, (char*)tmpkv[i].key.data, (char*)tmpkv[i].value.data);
    }

	if (ngx_http_demo_arg_strscript_eval(r, democf) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

    ngx_http_complex_value(r, democf->arg_compilecomplexvalue, &democf->arg_compilecomplexvalue_str);

    u_char buffer[1000];
    ngx_memset(buffer, 0, sizeof(buffer));
    ngx_sprintf(buffer,
            "arg_flag: %d\n"
			"arg_str: %V\n"
            "arg_num: %d\n"
            "arg_str_array: %s\n"
            "arg_keyval: %s\n"
            "arg_size: %d\n"
            "arg_off: %L\n"
            "arg_msec: %d\n"
            "arg_sec: %d\n"
            "arg_bufs:\n\tnum: %d\n\tsize: %d\n"
            "arg_enum: %d\n"
            "arg_bitmask: %d\n"
            "arg_strscript: %V\n"
            "arg_compilecomplexvalue: %V\n",
            democf->arg_flag, &democf->arg_str, democf->arg_num,
            (char*)buffer_strarray, (char*)buffer_keyval, democf->arg_size,
            democf->arg_off, democf->arg_msec, democf->arg_sec,
            democf->arg_bufs.num, democf->arg_bufs.size, democf->arg_enum,
			democf->arg_bitmask,
            &democf->arg_strscript,
            &democf->arg_compilecomplexvalue_str);
    ngx_str_t response = ngx_string(buffer);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ngx_strlen(buffer);
    r->headers_out.content_type = type;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ngx_buf_t *b;
    //b = ngx_create_temp_buf(r->pool, response.len);
    b = ngx_create_temp_buf(r->pool, ngx_strlen(buffer));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    //ngx_memcpy(b->pos, response.data, response.len);
    ngx_memcpy(b->pos, response.data, ngx_strlen(buffer));
    b->last = b->pos + ngx_strlen(buffer);
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static char *ngx_http_demo_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_demo_upstream_handler;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_demo_upstream_handler(ngx_http_request_t *r) {
    ngx_http_demo_ctx_t *democtx = ngx_http_get_module_ctx(r, ngx_http_demo_module);
    if (democtx == NULL) {
        democtx = ngx_palloc(r->pool, sizeof(ngx_http_demo_ctx_t));
        if (democtx == NULL)
            return NGX_ERROR;
        ngx_http_set_ctx(r, democtx, ngx_http_demo_module);
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }

    ngx_http_demo_loc_conf_t *democf;
    democf = ngx_http_get_module_loc_conf(r, ngx_http_demo_module);
    ngx_http_upstream_t *u = r->upstream;

    u->conf = &democf->upstreamconf;
    u->buffering = democf->upstreamconf.buffering;
    u->resolved = (ngx_http_upstream_resolved_t*)ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_pcalloc resolved error. %s.", strerror(errno));
        return NGX_ERROR;
    }
    static struct sockaddr_in backendSockAddr;
    //struct hostent *pHost = gethostbyname((char*)"www.weather.com.cn");
    struct hostent *pHost = gethostbyname((char*)"www.baidu.com");
    if (pHost == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
        return NGX_ERROR;
    }
    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t)8080);
    //char *pDmsIP = inet_ntoa(*(struct in_addr*)(pHost->h_addr_list[0]));
    //backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
    //backendSockAddr.sin_addr.s_addr = inet_addr("61.4.185.201");
    backendSockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    //democtx->backendServer.data = (u_char*)pDmsIP;
    //democtx->backendServer.len = strlen(pDmsIP);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, pHost->h_name);

    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    ngx_str_t host = ngx_string("www.weather.com.cn");
    u->resolved->host = host;
    u->resolved->port = htons((in_port_t)8080);
    u->resolved->naddrs = 1;

    u->create_request = demo_upstream_create_request;
    u->process_header = demo_upstream_process_status_line;
    u->finalize_request = demo_upstream_finalize_request;


    r->main->count++;
    ngx_http_upstream_init(r);
    return NGX_DONE;
}

static void* ngx_http_demo_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_demo_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_demo_loc_conf_t));
    if (conf==NULL) {
        return NGX_CONF_ERROR;
    }
    conf->arg_flag = NGX_CONF_UNSET;
    //conf->arg_str = NGX_CONF_UNSET_PTR;
    conf->arg_str_array = NGX_CONF_UNSET_PTR;
    //conf->arg_keyval = NGX_CONF_UNSET_PTR;
    conf->arg_num = NGX_CONF_UNSET_UINT;
    conf->arg_size = NGX_CONF_UNSET_SIZE;
    conf->arg_off = NGX_CONF_UNSET;
    conf->arg_msec = NGX_CONF_UNSET;
    conf->arg_sec = NGX_CONF_UNSET;
    conf->arg_enum = NGX_CONF_UNSET_UINT;
    conf->arg_msec = NGX_CONF_UNSET;

    conf->upstreamconf.connect_timeout = 5000;
    conf->upstreamconf.send_timeout = 5000;
    conf->upstreamconf.read_timeout = 5000;
    conf->upstreamconf.store_access = 0600;
    conf->upstreamconf.buffering = 0;
    conf->upstreamconf.bufs.num = 8;
    conf->upstreamconf.bufs.size = ngx_pagesize;
    conf->upstreamconf.buffer_size = ngx_pagesize;
    conf->upstreamconf.busy_buffers_size = 2*ngx_pagesize;
    conf->upstreamconf.temp_file_write_size = 2*ngx_pagesize;
    conf->upstreamconf.max_temp_file_size = 1024*1024*1024;
    conf->upstreamconf.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstreamconf.pass_headers = NGX_CONF_UNSET_PTR;

    return conf;
}

static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

static char* ngx_http_demo_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_demo_loc_conf_t *prev = parent;
    ngx_http_demo_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->arg_flag, prev->arg_flag, 1);
    ngx_conf_merge_str_value(conf->arg_str, prev->arg_str, "default");
    ngx_conf_merge_ptr_value(conf->arg_str_array, prev->arg_str_array, NULL);
    ngx_conf_merge_ptr_value(conf->arg_keyval, prev->arg_keyval, NULL);
    ngx_conf_merge_uint_value(conf->arg_num, prev->arg_num, 10);
    ngx_conf_merge_size_value(conf->arg_size, prev->arg_size, 1024);
    ngx_conf_merge_off_value(conf->arg_off, prev->arg_off, 1024*1024);
    ngx_conf_merge_msec_value(conf->arg_msec, prev->arg_msec, 5000);
    ngx_conf_merge_sec_value(conf->arg_sec, prev->arg_sec, 60);
    ngx_conf_merge_bufs_value(conf->arg_bufs, prev->arg_bufs, 4, 8192);
    ngx_conf_merge_uint_value(conf->arg_enum, prev->arg_enum, 0);
    ngx_conf_merge_bitmask_value(conf->arg_bitmask, prev->arg_bitmask,
                              (NGX_CONF_BITMASK_SET | NGX_http_demo_BIT1));
    ngx_conf_merge_str_value(conf->arg_str, prev->arg_str, "default");

    ngx_conf_merge_msec_value(conf->upstreamconf.connect_timeout, prev->upstreamconf.connect_timeout, 5000);

    ngx_hash_init_t hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstreamconf, &prev->upstreamconf, ngx_http_proxy_hide_headers, &hash) != NGX_OK )
        return NGX_CONF_ERROR;


    return NGX_CONF_OK;
}

static char* ngx_http_demo_arg_strscript(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_demo_loc_conf_t *dlcf = conf;

    ngx_str_t *value, *url;
    ngx_uint_t n;
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_script_compile_t sc;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_demo_handler;
    value = cf->args->elts;

    url = &value[1];
    n = ngx_http_script_variables_count(url);
    if (n) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &dlcf->arg_strscript_lengths;
        sc.values = &dlcf->arg_strscript_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_demo_arg_strscript_eval(ngx_http_request_t *r, ngx_http_demo_loc_conf_t *dlcf) {
    if (ngx_http_script_run(r, &dlcf->arg_strscript, dlcf->arg_strscript_lengths->elts, 0,
                            dlcf->arg_strscript_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static char* ngx_http_demo_arg_compilecomplexvalue(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_demo_loc_conf_t *dlcf = conf;
    ngx_http_compile_complex_value_t   ccv;
    ngx_str_t *value;

    value = cf->args->elts;
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    ccv.zero = 1;
    //ccv.conf_prefix = 1;
    ccv.root_prefix = 1;
    ngx_http_compile_complex_value(&ccv);
    dlcf->arg_compilecomplexvalue = ccv.complex_value;
    return NGX_CONF_OK;
}

static ngx_int_t demo_upstream_create_request(ngx_http_request_t *r) {
    //static ngx_str_t backendQueryLine = ngx_string("http://www.weather.com.cn/data/sk/101010100.html");
    //static ngx_str_t backendQueryLine = ngx_string("GET /data/sk/101010100.html");
    static ngx_str_t backendQueryLine = ngx_string("GET /index.html");
    //ngx_int_t queryLineLen = backendQueryLine.len + r->args.len - 2;
    ngx_int_t queryLineLen = backendQueryLine.len-1;
    ngx_buf_t* b = ngx_create_temp_buf(r->pool, queryLineLen);
    if (b==NULL) {
        return NGX_ERROR;
    }
    b->last = b->pos + queryLineLen;
    ngx_snprintf(b->pos, queryLineLen, (char*)backendQueryLine.data);
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if (r->upstream->request_bufs == NULL) {
        return NGX_ERROR;
    }

    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;

    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;

    r->header_hash = 1;


    return NGX_OK;
}

static ngx_int_t demo_upstream_process_header(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_table_elt_t *h;
    ngx_http_upstream_header_t *hh;
    ngx_http_upstream_main_conf_t *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    for (;;) {
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        if (rc == NGX_OK) {
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h==NULL) {
                return NGX_ERROR;
            }
            h->hash = r->header_hash;
            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool, h->key.len+1+h->value.len+1+h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }
            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;
            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);
            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash('s','e'), 'r'), 'v'), 'e'), 'r');
                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char*)"server";
            }

            if (r->upstream->headers_in.date == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash('d','a'), 't'), 'e');
                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char*)"date";
            }
            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid header");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    return NGX_OK;
}

static ngx_int_t demo_upstream_process_status_line(ngx_http_request_t *r) {
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u;

    ngx_http_demo_ctx_t *democtx = ngx_http_get_module_ctx(r, ngx_http_demo_module);
    if (democtx == NULL) {
        return NGX_ERROR;
    }
    u = r->upstream;

    rc = ngx_http_parse_status_line(r, &u->buffer, &democtx->status);
    if (rc == NGX_AGAIN) {
        return rc;
    }
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");
    }
    r->http_version = NGX_HTTP_VERSION_9;

    u->state->status = NGX_HTTP_OK;
    if (u->state) {
        u->state->status = democtx->status.code;
    }
    u->headers_in.status_n = democtx->status.code;

    len = democtx->status.end - democtx->status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, democtx->status.start, len);
    u->process_header = demo_upstream_process_header;

    return demo_upstream_process_header(r);
}

static void demo_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "mytest_upstream_finalize_request");
}
