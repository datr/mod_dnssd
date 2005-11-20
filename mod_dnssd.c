/*
 * $Id: mod_zeroconf.c,v 1.20 2004/10/07 15:30:25 sctemme Exp $
 *
 *  Copyright 2003, 2004 Sander Temme
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"

#include <howl.h>

/* Macro to test result of Howl functions */
#define TESTORBAIL(f) if ((f) != SW_OKAY) { \
                          return HTTP_INTERNAL_SERVER_ERROR; \
                      }

typedef struct zc_cfg {
    int enabled;
    char *serviceName;
    char *partialURI;
}
       zc_cfg;

sw_discovery howl_session;

module AP_MODULE_DECLARE_DATA zeroconf_module;

/*
 * Locate server configuration record for specified server
 */
static zc_cfg *our_sconfig(const server_rec *s)
{
    return (zc_cfg *) ap_get_module_config(s->module_config,
                                           &zeroconf_module);
}

static const char *cmd_zeroconf_enable(cmd_parms *cmd, void *mconfig,
                                            int enable)
{
    zc_cfg *cfg = our_sconfig(cmd->server);
    cfg->enabled = enable;
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, cmd->server,
                 "Zeroconf switched %s", enable ? "on" : "off");

    return NULL;
}

static const char *cmd_zeroconf_register(cmd_parms *cmd, void *mconfig,
                                              const char *serviceName,
                                              const char *partialURI)
{
    zc_cfg *cfg = our_sconfig(cmd->server);

    cfg->serviceName = (char *) serviceName;
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, cmd->server,
                 "Service Name is \"%s\"", cfg->serviceName);
    cfg->partialURI = (char *) partialURI;
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, cmd->server,
                 "Partial Path is %s",
                 (partialURI == NULL) ? "not set" : cfg->partialURI);
    return NULL;
}

static void *zc_create_server_config(apr_pool_t * p, server_rec *s)
{
    zc_cfg *cfg;

    cfg = (zc_cfg *) apr_palloc(p, sizeof(zc_cfg));
    cfg->enabled = 0;           /* Default to disabled */
    cfg->serviceName = NULL;
    cfg->partialURI = NULL;

    return (void *) cfg;
}

static void *zc_merge_server_config(apr_pool_t * p, void *server1_conf,
                                         void *server2_conf)
{
    zc_cfg *merged_cfg, *s1cfg, *s2cfg;
    merged_cfg = (zc_cfg *) apr_palloc(p, sizeof(zc_cfg));
    s1cfg = (zc_cfg *) server1_conf;
    s2cfg = (zc_cfg *) server2_conf;

    /*
     * Inherit the zeroconf enablement. Config language does not allow
     * turning it off, so just assume the main server value.
     */
    merged_cfg->enabled = s1cfg->enabled;
    /*
     * Don't care about any main server registration info.
     * Use vhost reg info, even if it's NULL.
     */
    merged_cfg->serviceName = s2cfg->serviceName;
    merged_cfg->partialURI = s2cfg->partialURI;

    return (void *) merged_cfg;
}

static sw_result howl_publish_reply(sw_discovery               rendezvous,
                                    sw_discovery_publish_status status,
                                    sw_discovery_oid            id,
                                    sw_opaque                   opaque)
{
    static sw_string status_text[] = {
        "Started",
        "Stopped",
        "Name Collision",
        "Invalid"
    };
    fprintf(stderr, "publish reply: %s\n", status_text[status]);
    return SW_OKAY;
}

static sw_result host_publish_reply(sw_discovery                rendezvous,
                                    sw_discovery_publish_status status,
                                    sw_discovery_oid            id,
                                    sw_opaque                   extra)
{
    static sw_string status_text[] = {
        "Started",
        "Stopped",
        "Name Collision",
        "Invalid"
    };
    fprintf(stderr, "host registration reply: %s\n", status_text[status]); 
    fprintf(stderr, "Host registration callback: %d\n", status);
    return SW_OKAY;
}

/*
 * Publish the hostname of server s through mDNS, using the IP 
 * address(es) that the server is bound to, if any. 
 *
 */

static int zc_register_host(server_rec *s)
{

    apr_sockaddr_t *mysock;
    apr_status_t aprstatus;
    char *thehostip;
    sw_result hr;
    sw_ipv4_address serveraddr;
    sw_discovery_oid host_id;

    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,
                 s, "Registering host with name %s",
                 s->server_hostname);
    for (mysock = s->addrs->host_addr; mysock;
         mysock = mysock->next) {
        /*
         * First, get the IP address string from the server
         * record
         */
        aprstatus = apr_sockaddr_ip_get(&thehostip, mysock);
        if (aprstatus != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, aprstatus, s,
                         "Failed to obtain server address");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG,
                     0, s, "Server bound to IP address [%s] port [%d][%d]",
                     thehostip, mysock->port,s->port);
        /*
         * Howl doesn't know what to do with IPv6 at this
         * time
         */
        if (mysock->family == APR_INET) {
	  if (mysock->sa.sin.sin_addr.s_addr != INADDR_ANY
	      && mysock->sa.sin.sin_addr.s_addr != INADDR_NONE) 
	    /* What about localhost ? */
	    {
	      hr = sw_ipv4_address_init_from_name(&serveraddr, thehostip);
            }
	  else {
	    hr = sw_ipv4_address_init_from_this_host(&serveraddr);
            }
        }
        hr = sw_discovery_publish_host(howl_session,
                           0,
                           s->server_hostname,
                           NULL,
                           serveraddr,
                           host_publish_reply,
                           (sw_opaque) s,
                           &host_id);
        if (hr != SW_OKAY) {
            ap_log_error(APLOG_MARK, APLOG_ERR, hr,
                         s,
                         "Failed to publish hostname \"%s\" "
                         "with IP address \"%s\"",
                         s->server_hostname, thehostip);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    return OK;
}

static int zc_post_config(apr_pool_t * pconf, apr_pool_t * plog,
                              apr_pool_t * ptemp, server_rec *s)
{
    void *data;
    sw_discovery_oid *pubidPtr;
    const char *userdata_key = "zeroconf_init_module";
    zc_cfg *cfg;
    sw_result howl_result;
    sw_discovery_oid howl_id;
    sw_port serverport;
    sw_text_record text_record;
    sw_octets pathinfo;
    sw_ulong pilength;
    char *thehostname;
#if APR_HAS_FORK
    apr_proc_t *callbackchild;
    apr_status_t forkstatus;
#endif
    server_rec *ws;             /* Walk Server; we need the top server_rec
                                 * later */

    /*    raise(SIGSTOP); */

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, s, 
                 "In post_config, userdata pointer is %#lx, pid is %d",
                 data, getpid());
    if (!data) {
        /*
         * Tell the world we've been here before, so we don't end up forking
         * more than one callback processes.
         */
        apr_pool_userdata_set((const void *) 1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
    } else {
        /* Check if Zeroconf has been enabled globally. If not, bail here */
        cfg = our_sconfig(s);
        if (cfg->enabled == 0) {
            return OK;
        }
        /* Still here? Let's go. */
        TESTORBAIL(sw_discovery_init(&howl_session));

        /*
         * Need to know the hostname of the machine, so we know not to
         * re-register an existing one
         */
        thehostname = apr_palloc(pconf, APRMAXHOSTLEN + 1);
        if (!thehostname) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (!APR_STATUS_IS_SUCCESS(apr_gethostname(thehostname,
                                                   APRMAXHOSTLEN, pconf))) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, s,
                     "The hostname is [%s]", thehostname);
        for (ws = s; ws; ws = ws->next) {
            cfg = our_sconfig(ws);
            if (cfg->serviceName) {
                if (cfg->partialURI) {
                    TESTORBAIL(sw_text_record_init(&text_record));
                    TESTORBAIL(sw_text_record_add_key_and_string_value(text_record, "path", 
                                                  cfg->partialURI));
                    pathinfo = sw_text_record_bytes(text_record);
                    pilength = sw_text_record_len(text_record);
                }
                else {
                    pathinfo = NULL;
                    pilength = 0;
                }
                /*
                 * for main server port is fetched from eg:
                 * ServerName hostnam:port
                 * 
                 * for virtualhost eg:
		 * <VirtualHost ip:port>
                 */
                serverport = ws->is_virtual ?  ws->addrs->host_port: ws->port;
                ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, ws,
                             "Publishing service with service name [%s]; "
                             "hostname [%s]; port [%d], path [%s]",
                             cfg->serviceName,
                             ws->server_hostname, serverport, cfg->partialURI);
                if (apr_strnatcasecmp(thehostname, ws->server_hostname) != 0) {
                    /* Shouldn't throw away the result here. What's up with
                     * that? 
                     */
                    zc_register_host(ws);
                }
                howl_result = sw_discovery_publish(howl_session,
                                                    0,
                                                    cfg->serviceName,
                                                    "_http._tcp",
                                                    NULL,
                                                    ws->server_hostname,
                                                    serverport,
                                                    pathinfo,
                                                    pilength,
                                                    howl_publish_reply,
                                                    (sw_opaque) ws, 
                                                    &howl_id);
                if (howl_result != SW_OKAY) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, howl_result,
                                 ws, "Failed to publish service %s",
                                 cfg->serviceName);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                pubidPtr = apr_palloc(s->process->pool,
                                      sizeof(sw_discovery_oid));
                if (!pubidPtr) {
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                /*
                 * Store publish ID in the server's pool userdata, using the
                 * serviceName as key. The serviceName should be unique, right?
                 */
                *pubidPtr = howl_id;
                apr_pool_userdata_set(pubidPtr, cfg->serviceName,
                                      apr_pool_cleanup_null,
                                      ws->process->pool);
            }                   /* serviceName set for server config */
        }                       /* Server walk */

        /*
         * On unix-like systems, we need to fork a child process to 
         * run the callback function. On Windows, this is not necessary.
         */
#if APR_HAS_FORK
        callbackchild = apr_palloc(s->process->pool, sizeof(apr_proc_t));
        if (callbackchild == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, 
                         "Allocating process struct memory from pool failed");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        switch(forkstatus = apr_proc_fork(callbackchild, s->process->pool)) {
        case APR_INCHILD: 
            /* I'm the child */
            sw_discovery_run(howl_session);
            /*
             * This function never returns ...
             */
            break; /* Not reached */
        case APR_INPARENT: 
            /* I'm the parent */
            apr_pool_note_subprocess(s->process->pool, callbackchild, 
                                     APR_KILL_AFTER_TIMEOUT);
            ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, s,
                         "Forked callback child process with pid [%d]",
                         callbackchild->pid);
            break;
        default: 
            /* FUBAR: log and bail */
            ap_log_error(APLOG_MARK, APLOG_ERR, forkstatus, s,
                         "Failed to fork callback child");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
#endif /* APR_HAS_FORK */
    }                           /* If first time run */
    return OK;
}

static void zc_register_hooks(apr_pool_t * p)
{
    ap_hook_post_config(zc_post_config, NULL, NULL, APR_HOOK_LAST);
}

static const command_rec zc_cmds[] = {
    AP_INIT_FLAG("Zeroconf",
                 cmd_zeroconf_enable,
                 NULL,
                 GLOBAL_ONLY,
                 "Enable/disable Zeroconf registration"),
    AP_INIT_TAKE12("ZeroconfRegister",
                   cmd_zeroconf_register,
                   NULL,
                   NOT_IN_DIR_LOC_FILE,
           "Register server or virtual host with Zeroconf mDNS responder.\n"
                 "Arguments are service name and, optionally, partial URI"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA zeroconf_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    zc_create_server_config,
    zc_merge_server_config,
    zc_cmds,
    zc_register_hooks,
};
