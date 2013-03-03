/* $Id$ */

/***
  Copyright 2006 Lennart Poettering

  Licensed under the Apache License, Version 2.0 (the "License"); you
  may not use this file except in compliance with the License.  You
  may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
  implied.  See the License for the specific language governing
  permissions and limitations under the License.
***/

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_log.h>
#include <apr_lib.h>
#include <ap_config.h>
#include <apr_strings.h>
#include <unixd.h>
#include <apr_signal.h>
#include <mpm_common.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <avahi-common/simple-watch.h>
#include <avahi-common/domain.h>
#include <avahi-common/error.h>
#include <avahi-common/alternative.h>
#include <avahi-common/gccmacro.h>
#include <avahi-common/malloc.h>
#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#define MOD_DNSSD_USERDATA_KEY "mod-dnssd"

static AvahiEntryGroup * _group = NULL;
static AvahiSimplePoll * _poll  = NULL;
static const char ** _cnames    = NULL;

struct runtime_data;

struct service_data {
    struct runtime_data *runtime;
    apr_pool_t *pool;

    char *host_name;
    uint16_t port;
    char *location;
    char *name;
    apr_array_header_t *txt_record;
    apr_array_header_t *types;
    int append_host_name;
    char *chosen_name;

    AvahiEntryGroup *group;

    struct service_data *next;
};

struct runtime_data {
    server_rec *main_server;
    AvahiClient *client;
    AvahiSimplePoll *simple_poll;
    struct global_config_data *global_config_data;
    apr_pool_t* pool;
    struct service_data *services;
};

struct global_config_data {
    int enabled;
    int user_dir;
    int vhost;
    const char *user_dir_path;
};

static int sigterm_pipe_fds[2] = { -1, -1 };

module AP_MODULE_DECLARE_DATA dnssd_module;

#define GET_CONFIG_DATA(s) ap_get_module_config((s)->module_config, &dnssd_module)

static int set_nonblock(int fd) {
    int n;

    ap_assert(fd >= 0);

    if ((n = fcntl(fd, F_GETFL)) < 0)
        return -1;

    if (n & O_NONBLOCK)
        return 0;

    return fcntl(fd, F_SETFL, n|O_NONBLOCK);
}

static void add_service(struct runtime_data *r, const char *host_name, uint16_t port, const char *location, const char *name, const char *types, int append_host_name, const char *txt_record) {
    struct service_data *d;
    char *w;
    ap_assert(r);

/*     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "add_service: %s %s %s %s", host_name, location, name, txt_record); */

    d = apr_palloc(r->pool, sizeof(struct service_data));
    ap_assert(d);

    d->pool = NULL;
    d->runtime = r;
    d->host_name = apr_pstrdup(r->pool, host_name);
    d->port = port;
    d->location = apr_pstrdup(r->pool, location);
    d->name = apr_pstrdup(r->pool, name);
    d->append_host_name = append_host_name;
    d->chosen_name = NULL;

    d->types = apr_array_make(r->pool, 4, sizeof(char*));

    if (types)
        while (*(w = ap_getword_conf(r->pool, &types)) != 0)
            *(char**) apr_array_push(d->types) = w;

    d->txt_record = apr_array_make(r->pool, 4, sizeof(char*));

    if (txt_record)
        while (*(w = ap_getword_conf(r->pool, &txt_record)) != 0)
            *(char**) apr_array_push(d->txt_record) = w;

    d->group = NULL;

    d->next = r->services;
    r->services = d;

/*     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "done"); */

}

static void assemble_services(struct runtime_data *r) {
    ap_directive_t *v;
    const char *default_host_name = NULL;
    uint16_t default_port = 0;
    struct service_data *j;
    apr_pool_t *t;

    ap_assert(r);

    apr_pool_create(&t, r->pool);

    for (v = ap_conftree; v; v = v->next) {
        const char *a = v->args;

        if (strcasecmp(v->directive, "ServerName") == 0) {
            const char *tdhn = NULL;
            char *colon;
            tdhn = ap_getword_conf(t, &a);
            colon = strrchr(tdhn, ':');
            if (colon) {
                apr_size_t sz;
                if (!default_port) {
                        default_port = (uint16_t) atoi(colon+1);
                }
                sz = colon - tdhn;
                default_host_name = apr_pstrndup(t, tdhn, sz);
            } else {
                default_host_name = tdhn;
            }
        } else if (strcasecmp(v->directive, "Listen") == 0) {
            char *sp;

            if (!default_port) {
                char *colon;

                sp = ap_getword_conf(t, &a);
                if ((colon = strrchr(sp, ':')))
                    sp = colon + 1;

                default_port = (uint16_t) atoi(sp);
            }
        } else if (strcasecmp(v->directive, "DNSSDServicePort") == 0)

            default_port = (uint16_t) atoi(a);

        else if (strcasecmp(v->directive, "<VirtualHost") == 0) {
            const char *host_name = NULL;
            uint16_t vport = 0;
            const char *vname = NULL, *vtypes = NULL, *txt_record = NULL;
            ap_directive_t *l;
            char *colon;
            struct service_data *marker = r->services;

            if ((colon = strrchr(v->args, ':')))
                vport = (uint16_t) atoi(colon+1);

/*             ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "VHOST: %s ", v->directive);  */

            for (l = v->first_child; l; l = l->next) {
                a = l->args;

/*                 ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "VHOST_INTERNAL %s | %s | %s | %s", l->directive, l->args, vname, vtypes);  */

                if (strcasecmp(l->directive, "ServerName") == 0) {
                    const char *thn = NULL;
                    thn = ap_getword_conf(t, &a);
                    colon = strrchr(thn, ':');
                    if (colon) {
                        apr_size_t sz;
                        if (!vport)
                            vport = (uint16_t) atoi(colon+1);
                        sz = colon - thn;
                        host_name = apr_pstrndup(t, thn, sz);
                    } else {
                        host_name = thn;
                    }
                }
                else if (strcasecmp(l->directive, "DNSSDServiceName") == 0)
                    vname = ap_getword_conf(t, &a);
                else if (strcasecmp(l->directive, "DNSSDServiceTypes") == 0)
                    vtypes = a;
                else if (strcasecmp(l->directive, "DNSSDServicePort") == 0)
                    vport = (uint16_t) atoi(a);
                else if (strcasecmp(l->directive, "DNSSDServiceTxtRecord") == 0)
                    txt_record = a;
                else if (strcasecmp(l->directive, "<Location") == 0) {
                    ap_directive_t *s;
                    const char *sname = NULL, *stypes = NULL;
                    char *path;
                    size_t i;
                    uint16_t sport = 0;

                    path = apr_pstrdup(t, l->args);

                    if (*path != 0 && (path[(i = strlen(path) - 1)] == '>'))
                        path[i] = 0;

                    for (s = l->first_child; s; s = s->next) {
                        a = s->args;

                        if (strcasecmp(s->directive, "DNSSDServiceName") == 0)
                            sname = ap_getword_conf(t, &a);
                        else if (strcasecmp(s->directive, "DNSSDServiceTypes") == 0)
                            stypes = a;
                        else if (strcasecmp(s->directive, "DNSSDServiceTxtRecord") == 0)
                            txt_record = a;
                        else if (strcasecmp(s->directive, "DNSSDServicePort") == 0)
                            sport = (uint16_t) atoi(a);
                    }

                    if (sname)
                        add_service(r, NULL, sport, path, sname, stypes, 0, txt_record);
                }
            }

            /* Fill in missing data in <Location> based services */
            for (j = r->services; j && j != marker; j = j->next) {
                if (!j->pool)
                    j->port = vport;
                j->host_name = apr_pstrdup(r->pool, host_name);
            }

            if (r->global_config_data->vhost || vname || vtypes || txt_record)
                add_service(r, host_name, vport, NULL, vname ? vname : host_name, vtypes, 0, txt_record);
        }
    }

/*     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "ping");  */

    if (r->global_config_data->user_dir) {
        struct passwd *pw;
        apr_pool_t *p_loop;

        apr_pool_create(&p_loop, t);

        while ((pw = getpwent())) {
            apr_finfo_t finfo;
            char *path;
            const char *u;

            apr_pool_clear(p_loop);

            if (pw->pw_uid < 500)
                continue;

            if (*pw->pw_dir == 0 || strcmp(pw->pw_dir, "/") == 0)
                continue;

            path = apr_pstrcat(p_loop, pw->pw_dir, "/", r->global_config_data->user_dir_path, NULL);

            if (apr_stat(&finfo, path, APR_FINFO_TYPE, p_loop) != APR_SUCCESS)
                continue;

            if (finfo.filetype != APR_DIR)
                continue;

            if (access(path, X_OK) != 0)
                continue;

            if (pw->pw_gecos && *pw->pw_gecos) {
                char *comma;
                u = apr_pstrdup(p_loop, pw->pw_gecos);
                if ((comma = strchr(u, ',')))
                    *comma = 0;
            } else
                u = pw->pw_name;

            add_service(r, NULL, 0, apr_pstrcat(p_loop, "/~", pw->pw_name, NULL), apr_pstrcat(p_loop, u, " on ", NULL), NULL, 1, NULL);
        }

        endpwent();

        apr_pool_destroy(p_loop);
    }

    if (!default_port)
        default_port = 80;

    /* Fill in missing data in all services */
    for (j = r->services; j; j = j->next) {
        if (!j->port)
            j->port = default_port;

        if (!j->host_name)
            j->host_name = apr_pstrdup(r->pool, default_host_name);

        if (!j->name)
            j->name = apr_pstrdup(r->pool, j->host_name);
    }

    apr_pool_destroy(t);
}

static void create_service(struct service_data *j);

static void service_callback(AVAHI_GCC_UNUSED AvahiEntryGroup *g, AvahiEntryGroupState state, void *userdata) {
    struct service_data *j = userdata;

    switch (state) {
        case AVAHI_ENTRY_GROUP_UNCOMMITED:
        case AVAHI_ENTRY_GROUP_REGISTERING:
        case AVAHI_ENTRY_GROUP_ESTABLISHED:
            break;

        case AVAHI_ENTRY_GROUP_COLLISION: {

            char *n;
            ap_assert(j->chosen_name);

            n = avahi_alternative_service_name(j->chosen_name);
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, j->runtime->main_server, "Name collision on '%s', changing to '%s'", j->chosen_name, n);

            apr_pool_clear(j->pool);
            j->chosen_name = apr_pstrdup(j->pool, n);

            create_service(j);

            break;
        }

        case AVAHI_ENTRY_GROUP_FAILURE:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, j->runtime->main_server, "Failed to register service: %s", avahi_strerror(avahi_client_errno(j->runtime->client)));
            break;
    }
}

static void create_service(struct service_data *j) {
    apr_pool_t *t;
    const char *n;
    char *p;
    struct runtime_data *r = j->runtime;
    char **type, **txt_record;
    AvahiStringList *strlist = NULL;


    if (!j->group)
        if (!(j->group = avahi_entry_group_new(r->client, service_callback, j))) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "avahi_entry_group_new() failed: %s", avahi_strerror(avahi_client_errno(r->client)));
            return;
        }

    ap_assert(j->group);
    ap_assert(avahi_entry_group_is_empty(j->group));

    apr_pool_create(&t, r->pool);

/*         ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "Service <%s>, host <%s>, port <%u>, location <%s>", j->name, j->host_name, j->port, j->location); */

    if (j->chosen_name)
        n = j->chosen_name;
    else if (!j->name)
        n = avahi_client_get_host_name(r->client);
    else if (j->append_host_name)
        n = apr_pstrcat(t, j->name, avahi_client_get_host_name(r->client), NULL);
    else
        n = j->name;

    if (!j->pool)
        apr_pool_create(&j->pool, r->pool);

    if (n != j->chosen_name) {
        apr_pool_clear(j->pool);
        j->chosen_name = apr_pstrdup(j->pool, n);
    }

    p = j->location ? apr_pstrcat(t, "path=", j->location, NULL) : NULL;

/*         ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "%s, %s", p, n); */

    txt_record = (char **) j->txt_record->elts;

    for ( ; *txt_record ; txt_record++)
       strlist =  avahi_string_list_add(strlist, *txt_record);

    if (p)
        strlist = avahi_string_list_add(strlist, p);

    if (apr_is_empty_array(j->types)) {

        if (avahi_entry_group_add_service_strlst(
                j->group,
                AVAHI_IF_UNSPEC,
                AVAHI_PROTO_UNSPEC,
                0,
                n,
                j->port == 443 ? "_https._tcp" : "_http._tcp",
                NULL,
                j->host_name,
                j->port,
                strlist) < 0) {

            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "avahi_entry_group_add_service_strlst(\"%s\") failed: %s", n, avahi_strerror(avahi_client_errno(r->client)));
        }

        const char * cnames = {j->host_name, NULL};
        PublishAvahiCNames(cnames);

    } else {

        for (type = (char**) j->types->elts; *type; type++) {

            if (avahi_entry_group_add_service_strlst(
                    j->group,
                    AVAHI_IF_UNSPEC,
                    AVAHI_PROTO_UNSPEC,
                    0,
                    n,
                    *type,
                    NULL,
                    j->host_name,
                    j->port,
                    strlist) < 0) {

                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "avahi_entry_group_add_service_strlst(\"%s\") failed: %s", n, avahi_strerror(avahi_client_errno(r->client)));
            }

            const char * cnames = {j->host_name, NULL};
            PublishAvahiCNames(cnames);
        }
    }

    avahi_string_list_free(strlist);

    if (avahi_entry_group_is_empty(j->group)) {
        avahi_entry_group_free(j->group);
        j->group = NULL;
    } else
        avahi_entry_group_commit(j->group);

    apr_pool_destroy(t);
}

static void create_all_services(struct runtime_data *r) {
    struct service_data *j;
    ap_assert(r);

    for (j = r->services; j; j = j->next)
        create_service(j);
}

static void reset_services(struct runtime_data *r) {
    struct service_data *j;

    ap_assert(r);

    for (j = r->services; j; j = j->next) {
        if (j->group)
            avahi_entry_group_reset(j->group);

        if (j->pool)
            apr_pool_clear(j->pool);

        j->chosen_name = NULL;
    }
}

static void free_services(struct runtime_data *r) {
    struct service_data *j;

    ap_assert(r);

    for (j = r->services; j; j = j->next) {

        if (j->group) {
            avahi_entry_group_free(j->group);
            j->group = NULL;
        }

        if (j->pool)
            apr_pool_clear(j->pool);

        j->chosen_name = NULL;
    }
}

/* Called whenever the entry group state changes */
static void entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, AVAHI_GCC_UNUSED void *userdata) 
{
   assert(g == _group || _group == NULL);
   _group = g;

   switch (state) {
      case AVAHI_ENTRY_GROUP_FAILURE :
         fprintf(stderr, "Entry group failure: %s\n", avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));
         avahi_simple_poll_quit(_poll);
      break;

      case AVAHI_ENTRY_GROUP_COLLISION : 
      case AVAHI_ENTRY_GROUP_ESTABLISHED :
      case AVAHI_ENTRY_GROUP_UNCOMMITED:
      case AVAHI_ENTRY_GROUP_REGISTERING:
         /* empty */
      break;
   }
}

static void create_cnames(AvahiClient *c) 
{
   /* If this is the first time we're called, let's create a new entry group if necessary */
   if ((!_group)&&(!(_group = avahi_entry_group_new(c, entry_group_callback, NULL))))
   {
      fprintf(stderr, "avahi_entry_group_new() failed: %s\n", avahi_strerror(avahi_client_errno(c)));
      goto fail;
   }

   /* If the group is empty (either because it was just created, or because it was reset previously, add our entries. */
   if (avahi_entry_group_is_empty(_group)) 
   {
      char hostname[HOST_NAME_MAX+64] = ".";  /* this dot will be overwritten with a count-byte, below */
      if (gethostname(&hostname[1], sizeof(hostname)-1) < 0) perror("gethostname");
      strncat(hostname, ".local", sizeof(hostname));
      hostname[sizeof(hostname)-1] = '\0';  /* paranoia? */

      /* Convert the hostname string into DNS's labelled-strings format */
      int hostnameLen = strlen(hostname);
      char count = 0;
      int i;
      for (i=hostnameLen-1; i>=0; i--)
      {
         if (hostname[i] == '.')
         {
            hostname[i] = count;
            count = 0;
         }
         else count++;
      }

      for (i=0; (_cnames[i] != NULL); i++)
      {
         int ret = avahi_entry_group_add_record(_group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, (AvahiPublishFlags)(AVAHI_PUBLISH_USE_MULTICAST|AVAHI_PUBLISH_ALLOW_MULTIPLE), _cnames[i], AVAHI_DNS_CLASS_IN, AVAHI_DNS_TYPE_CNAME, AVAHI_DEFAULT_TTL, hostname, hostnameLen+1); 
         if (ret >= 0) printf("Published DNS-SD hostname alias [%s]\n", _cnames[i]);
         else
         {
            fprintf(stderr, "Failed to add CNAME record [%s]: %s\n", _cnames[i], avahi_strerror(ret));
            goto fail;
         }
      }

      int ret = avahi_entry_group_commit(_group);
      if (ret < 0)
      {
         fprintf(stderr, "Failed to commit entry group: %s\n", avahi_strerror(ret));
         goto fail;
      }
   }
   return;

fail:
   avahi_simple_poll_quit(_poll);
}

/* Called whenever the client or server state changes */
static void client_callback(AvahiClient *c, AvahiClientState state, void *userdata) {
    struct runtime_data *r = userdata;

    ap_assert(r);

    r->client = c;

/*     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->main_server, "client_callback(%u)", state); */

    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            create_all_services(r);
            create_cnames(c);
            break;

        case AVAHI_CLIENT_S_COLLISION:
            reset_services(r);
            if (_group) avahi_entry_group_reset(_group);
            break;

        case AVAHI_CLIENT_FAILURE:

            if (avahi_client_errno(c) == AVAHI_ERR_DISCONNECTED) {
                int error;

                free_services(r);
                avahi_client_free(r->client);

                if ((r->client = avahi_client_new(avahi_simple_poll_get(r->simple_poll), AVAHI_CLIENT_NO_FAIL, client_callback, r, &error)))
                    break;

                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "avahi_client_new() failed: %s", avahi_strerror(error));
            } else
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->main_server, "Client failure: %s", avahi_strerror(avahi_client_errno(c)));

            avahi_simple_poll_quit(r->simple_poll);
            avahi_simple_poll_quit(_poll);

            break;

        case AVAHI_CLIENT_S_REGISTERING:
            if (_group) avahi_entry_group_reset(_group);
            break;

        case AVAHI_CLIENT_CONNECTING:
            /* do nothing */
            break;
    }

}

/** cnames should be a NULL-terminated array of alias hostnames for this host.
  * Example invocation:  const char * cnames = {"foo.local", "bar.local", NULL}; PublishAvahiCNames(cnames);  
  * Note that this function normally does not ever return!
  */
void PublishAvahiCNames(const char ** cnames)
{
   _cnames = cnames;

   /* Allocate main loop object */
   _poll = avahi_simple_poll_new();
   if (_poll)
   {
      int error;
      AvahiClient * client = avahi_client_new(avahi_simple_poll_get(_poll), (AvahiClientFlags) 0, client_callback, NULL, &error);
      if (client)
      {
         avahi_simple_poll_loop(_poll);
         avahi_client_free(client);
      }
      else fprintf(stderr, "Failed to create Avahi client: %s\n", avahi_strerror(error));

      avahi_simple_poll_free(_poll);
   }
   else fprintf(stderr, "Failed to create Avahi simple poll object.\n");
}

static void sigterm(AVAHI_GCC_UNUSED int s) {
    const char c = 'x';
    write(sigterm_pipe_fds[1], &c, sizeof(c));
}

static void watch_callback(AvahiWatch *w, int fd, AvahiWatchEvent event, void *userdata) {
    char c;
    ssize_t l;
    struct runtime_data *r = userdata;

    ap_assert(w);
    ap_assert(fd == sigterm_pipe_fds[0]);
    ap_assert(event == AVAHI_WATCH_IN);
    ap_assert(r);

    l = read(fd, &c, sizeof(c));
    ap_assert(l == sizeof(c));

    avahi_simple_poll_quit(r->simple_poll);
}

static void child_process(apr_pool_t *p, server_rec *server, struct global_config_data *d) {
    struct runtime_data r;
    int error;
    const AvahiPoll *api;
    AvahiWatch *w;

    ap_assert(d);

    unixd_setup_child();

    if (pipe(sigterm_pipe_fds) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r.main_server, "pipe() failed: %s", strerror(errno));
        goto quit;
    }

    set_nonblock(sigterm_pipe_fds[0]);
    set_nonblock(sigterm_pipe_fds[1]);

    apr_signal(SIGTERM, sigterm);
    apr_signal(SIGHUP, sigterm);
    apr_signal(AP_SIG_GRACEFUL, SIG_IGN);

    r.main_server = server;
    r.global_config_data = d;
    r.client = NULL;
    r.simple_poll = NULL;
    r.services = NULL;
    apr_pool_create(&r.pool, p);

/*      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r.main_server, "Child process startup pid=%lu", (unsigned long) getpid());  */

    assemble_services(&r);

    if (!r.services) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r.main_server, __FILE__": No services found to register");
        goto quit;
    }

    if (!(r.simple_poll = avahi_simple_poll_new())) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r.main_server, "avahi_simple_poll_new() failed: %s", strerror(errno));
        goto quit;
    }

    api = avahi_simple_poll_get(r.simple_poll);
    w = api->watch_new(api, sigterm_pipe_fds[0], AVAHI_WATCH_IN, watch_callback, &r);
    ap_assert(w);

    if (!(r.client = avahi_client_new(avahi_simple_poll_get(r.simple_poll), AVAHI_CLIENT_NO_FAIL, client_callback, &r, &error))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r.main_server, "avahi_client_new() failed: %s", avahi_strerror(error));
        goto quit;
    }

/*     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r.main_server, "Child process running");   */

    avahi_simple_poll_loop(r.simple_poll);

quit:

    if (r.client)
        avahi_client_free(r.client);

    if (r.simple_poll)
        avahi_simple_poll_free(r.simple_poll);

    if (r.pool)
        apr_pool_destroy(r.pool);

    if (sigterm_pipe_fds[0] >= 0)
        close(sigterm_pipe_fds[0]);

    if (sigterm_pipe_fds[1] >= 0)
        close(sigterm_pipe_fds[1]);

    sigterm_pipe_fds[0] = sigterm_pipe_fds[1] = -1;

/*      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r.main_server, "Child process ending"); */
}

static int start_child_process(apr_pool_t *p, server_rec *server, struct global_config_data *d) {
    apr_proc_t* proc;
    apr_status_t status;

/*     ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server, "Spawning child pid=%lu", (unsigned long) getpid()); */

    proc = apr_palloc(p, sizeof(apr_proc_t));
    ap_assert(proc);

    switch (status = apr_proc_fork(proc, p)) {

        case APR_INCHILD:
            child_process(p, server, d);
            exit(1);
            /* never reached */
            break;

        case APR_INPARENT:
            apr_pool_note_subprocess(p, proc, APR_KILL_ONLY_ONCE);
/*             ap_log_error(APLOG_MARK, APLOG_NOTICE, status, server, "Child process %lu", (unsigned long) proc->pid); */

            break;

        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, status, server, "apr_proc_fork() failed");
            return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

static int post_config(
    apr_pool_t *pconf,
    AVAHI_GCC_UNUSED apr_pool_t *plog,
    AVAHI_GCC_UNUSED apr_pool_t *ptemp,
    server_rec *s) {

    void *flag;
    struct global_config_data *d = GET_CONFIG_DATA(s);

    /* All post_config hooks are called twice, we're only interested in the second call. */

    apr_pool_userdata_get(&flag, MOD_DNSSD_USERDATA_KEY, s->process->pool);
    if (!flag) {
        apr_pool_userdata_set((void*) 1, MOD_DNSSD_USERDATA_KEY, apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    if (d->enabled)
        return start_child_process(pconf, s, d);

    return OK;
}

static void register_hooks(AVAHI_GCC_UNUSED apr_pool_t *p){
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_LAST);
}

static void *create_server_config(apr_pool_t *p, AVAHI_GCC_UNUSED server_rec *s) {
    struct global_config_data *d;

    d = apr_palloc(p, sizeof(struct global_config_data));
    ap_assert(d);

    d->enabled = 0;
    d->user_dir = 1;
    d->vhost = 1;
    d->user_dir_path = "public_html";

    return d;
}

static const char *cmd_dnssd_enable(
    cmd_parms *cmd,
    AVAHI_GCC_UNUSED void *mconfig,
    int enable) {

    struct global_config_data *d = GET_CONFIG_DATA(cmd->server);
    const char *err;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY)))
        return err;

    d->enabled = enable;
    return NULL;
}

static const char *cmd_dnssd_enable_user_dir(
    cmd_parms *cmd,
    AVAHI_GCC_UNUSED void *mconfig,
    int enable) {

    struct global_config_data *d = GET_CONFIG_DATA(cmd->server);
    const char *err;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY)))
        return err;

    d->user_dir = enable;
    return NULL;
}

static const char *cmd_dnssd_enable_vhost(
    cmd_parms *cmd,
    AVAHI_GCC_UNUSED void *mconfig,
    int enable) {

    struct global_config_data *d = GET_CONFIG_DATA(cmd->server);
    const char *err;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY)))
        return err;

    d->vhost = enable;
    return NULL;
}

static const char *cmd_dnssd_user_dir_path(
    cmd_parms *cmd,
    AVAHI_GCC_UNUSED void *mconfig,
    const char *value) {

    struct global_config_data *d = GET_CONFIG_DATA(cmd->server);
    const char *err;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY)))
        return err;

    if (value[0] == '~')
        return "Bad syntax";

    d->user_dir_path = value;

    return NULL;
}

static const char *cmd_dnssd_service_name(
    cmd_parms *cmd,
    AVAHI_GCC_UNUSED void *mconfig,
    const char *value) {

    const char *err;

    if ((err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES|NOT_IN_LIMIT)))
        return err;

    if (!avahi_is_valid_service_name(value))
        return "Invalid service name";

    return NULL;
}

static const char *cmd_dnssd_service_type(
    cmd_parms *cmd,
    AVAHI_GCC_UNUSED void *mconfig,
    const char *value) {

    const char *err;

    if ((err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES|NOT_IN_LIMIT)))
        return err;

    if (!avahi_is_valid_service_type_strict(value))
        return "Invalid service type";

    return NULL;
}

static const char *cmd_dnssd_service_port(
    cmd_parms *cmd,
    AVAHI_GCC_UNUSED void *mconfig,
    const char *value) {

    const char *err;
    int i;

    if ((err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES|NOT_IN_LIMIT)))
        return err;

    i = atoi(value);
    if (i <= 0 || i > 0xFFFF)
        return "Invalid port number";

    return NULL;
}

static const char *cmd_dnssd_service_txt_record(
    cmd_parms *cmd,
    AVAHI_GCC_UNUSED void *mconfig,
    AVAHI_GCC_UNUSED const char *value) {

    const char *err;

    if ((err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES|NOT_IN_LIMIT)))
        return err;

    return NULL;
}

static const command_rec commands[] = {

    AP_INIT_FLAG(
        "DNSSDEnable",
        cmd_dnssd_enable,
        NULL,
        RSRC_CONF,
        "Enable/disable DNS-SD registration entirely (default: no)"),

    AP_INIT_FLAG(
        "DNSSDAutoRegisterUserDir",
        cmd_dnssd_enable_user_dir,
        NULL,
        RSRC_CONF,
        "Enable/disable DNS-SD registration of ~/public_html (default: yes)"),

    AP_INIT_FLAG(
        "DNSSDAutoRegisterVHosts",
        cmd_dnssd_enable_vhost,
        NULL,
        RSRC_CONF,
        "Enable/disable DNS-SD registration of all virtual hosts (default: yes)"),

    AP_INIT_TAKE1(
        "DNSSDUserDir",
        cmd_dnssd_user_dir_path,
        NULL,
        RSRC_CONF,
        "Set the user directory to use instead of public_html"),

    AP_INIT_TAKE1(
        "DNSSDServiceName",
        cmd_dnssd_service_name,
        NULL,
        OR_OPTIONS,
        "Set the DNS-SD service name"),

    AP_INIT_ITERATE(
        "DNSSDServiceTypes",
        cmd_dnssd_service_type,
        NULL,
        OR_OPTIONS,
        "Set one or more DNS-SD service types"),

    AP_INIT_ITERATE(
        "DNSSDServicePort",
        cmd_dnssd_service_port,
        NULL,
        OR_OPTIONS,
        "Set the IP port this service should be accessed with."),

     AP_INIT_ITERATE(
        "DNSSDServiceTxtRecord",
        cmd_dnssd_service_txt_record,
        NULL,
        OR_OPTIONS,
        "Set one or more DNS-SD TXT records"),

    { NULL }
};

module AP_MODULE_DECLARE_DATA dnssd_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    create_server_config,  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    commands,              /* table of config file commands */
    register_hooks         /* register hooks */
};

/* vim:set expandtab: */
