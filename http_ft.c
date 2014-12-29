#define PURPLE_PLUGINS

#include <glib.h>

#include <errno.h>
#include <string.h>
#include <glib/gi18n.h>
#include <sys/types.h>
#ifdef __GNUC__
#include	<unistd.h>
#include	<fcntl.h>
#endif

#ifndef G_GNUC_NULL_TERMINATED
#	if __GNUC__ >= 4
#		define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#	else
#		define G_GNUC_NULL_TERMINATED
#	endif /* __GNUC__ >= 4 */
#endif /* G_GNUC_NULL_TERMINATED */

#ifdef _WIN32
#	include "win32dep.h"
#	define dlopen(a,b) LoadLibrary(a)
#	define RTLD_LAZY
#	define dlsym(a,b) GetProcAddress(a,b)
#	define dlclose(a) FreeLibrary(a)
#else
#	include <arpa/inet.h>
#	include <dlfcn.h>
#	include <netinet/in.h>
#	include <sys/socket.h>
#endif

#include <time.h>

#include "network.h"
#include "eventloop.h"
#include "plugin.h"
#include "prefs.h"
#include "request.h"
#include "debug.h"
#include "sslconn.h"
#include "ft.h"
#include "blist.h"

#define PREFS_BASE		"/plugins/core/http_ft"
#define PREF_PORT		PREFS_BASE "/port_number"
#define PREF_USERNAME	PREFS_BASE "/username"
#define PREF_PASSWORD	PREFS_BASE "/password"

static PurpleNetworkListenData *listen_data = NULL;
static guint input_handle = 0;
static gint listenfd = -1;
static GHashTable *resource_handlers = NULL;
static GHashTable *mapped_files = NULL;

typedef struct _JuiceHandles {
	guint http_input_handle;
	gint acceptfd;
	GString *databuffer;
} JuiceHandles;

static GHashTable *
juice_parse_query(const gchar *query)
{
	GHashTable *$_GET;
	gchar** pairs, *pair[2], **url_encoded_pair;
	int i;
	
	//Setup a php-like $_GET array (hash table)
	$_GET = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	
	if (query == NULL)
		return $_GET;
	
	pairs = g_strsplit(query, "&", -1);
	for (i = 0; pairs[i]; i++)
	{
		url_encoded_pair = g_strsplit(pairs[i], "=", 2);
		if (url_encoded_pair[0] != NULL)
		{
			pair[0] = g_strdup(purple_url_decode(url_encoded_pair[0]));
			if (url_encoded_pair[1] != NULL)
				pair[1] = g_strdup(purple_url_decode(url_encoded_pair[1]));
			else
				pair[1] = g_strdup("");
			
			purple_debug_info("http_ft", "Adding %s, %s to hash table.\n", pair[0], pair[1]);
			g_hash_table_insert($_GET, pair[0], pair[1]);
		}
		g_strfreev(url_encoded_pair);
	}
	g_strfreev(pairs);
	
	return $_GET;
}

static GHashTable *
juice_parse_headers(const gchar *head)
{
	GHashTable *headers;
	gchar **lines, **pair;
	int i;
	
	headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (head == NULL)
		return headers;
	
	lines = g_strsplit(head, "\r\n", -1);
	for (i = 0; lines[i]; i++)
	{
		pair = g_strsplit(lines[i], ": ", 2);
		if (pair[0] != NULL)
		{
			g_hash_table_insert(headers, g_strdup(pair[0]), g_strdup(pair[1]));
		}
		g_strfreev(pair);
	}
	g_strfreev(lines);
	
	return headers;
}

#if 0
#include <zlib.h>
guchar *
juice_gzip_data(gchar *data, gssize in_len, gssize *out_len)
{
	z_stream zstr;
	int gzip_err = 0;
	gchar *data_buffer;
	gulong gzip_len = G_MAXUINT16;
	GString *output_string;
	const char GZ_HEADER[10] = {0x1f, 0x8b, Z_DEFLATED, 0, 0, 0, 0, 0, 0, 3};
	
	data_buffer = g_new0(gchar, gzip_len);
	
	zstr.next_in = NULL;
	zstr.avail_in = 0;
	zstr.zalloc = Z_NULL;
	zstr.zfree = Z_NULL;
	zstr.opaque = 0;
	
	gzip_err = deflateInit2(&zstr, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
	if (gzip_err != Z_OK)
	{
		g_free(data_buffer);
		purple_debug_error("http_ft", "No built-in gzip support in zlib\n");
		return NULL;
	}
	
	zstr.next_in = (Bytef *) data;
	zstr.avail_in = in_len;
	zstr.next_out = (Bytef *)data_buffer;
	zstr.avail_out = gzip_len;
	
	gzip_err = inflate(&zstr, Z_SYNC_FLUSH);
	if (gzip_err != Z_OK)
	{
		g_free(data_buffer);
		purple_debug_error("http_ft", "Cannot encode gzip data\n");
		return NULL;
	}
	
	output_string = g_string_new(GZ_HEADER);
	while (gzip_err == Z_OK)
	{
		//append data to buffer
		output_string = g_string_append_len(output_string, data_buffer, gzip_len - zstr.avail_out);
		//reset buffer pointer
		zstr.next_out = (Bytef *)data_buffer;
		zstr.avail_out = gzip_len;
		gzip_err = inflate(&zstr, Z_SYNC_FLUSH);
	}
}
#endif

typedef struct _JuiceRequestObject {
	const gchar *first_line;
	const gchar *headers;
	const gchar *postdata;
	
	const gchar *uri;
	const gchar *request_type;
	
	const gchar *filename;
	const gchar *query;
} JuiceRequestObject;

typedef gboolean (*JuiceResourceHandlerFunc)(JuiceRequestObject *request, GHashTable *$_GET, gchar **response, gsize *response_length);

static gboolean
juice_add_resource_handler(const gchar *resource, JuiceResourceHandlerFunc handler)
{
	if (g_hash_table_lookup(resource_handlers, resource))
		return FALSE;
	
	g_hash_table_insert(resource_handlers, g_strdup(resource), handler);
	return TRUE;
}

static gboolean
random_url_resource_handler(JuiceRequestObject *request, GHashTable *$_GET, gchar **response, gsize *response_length)
{
	gboolean success;
	GError *error = NULL;
	const gchar *real_filename;
	
	real_filename = g_hash_table_lookup(mapped_files, request->filename);
	if (!real_filename || !*real_filename) {
		return FALSE;
	}
	
	success = g_file_get_contents(real_filename, response, response_length, &error);
	if (!success) {
		if (error) {
			purple_debug_error("http_ft", "error: %s\n", error->message);
			g_error_free(error);
		}
		return FALSE;
	}
	
	return TRUE;
}

static void
juice_handle_request(JuiceRequestObject *request, gint output_fd)
{
	JuiceResourceHandlerFunc handler;
	GHashTable *$_GET;
	gchar *response;
	gsize response_len;
	GString *reply_string;
	
	handler = g_hash_table_lookup(resource_handlers, request->filename);
	//if (handler == NULL)
	//	handler = juice_default_resource_handler;
	
	$_GET = juice_parse_query(request->query);
	
	if (handler != NULL && handler(request, $_GET, &response, &response_len))
	{
		reply_string = g_string_new(NULL);
		g_string_append(reply_string, "HTTP/1.0 200 OK\r\n");
		/* set appropriate mime type */
		if (g_str_has_suffix(request->filename, ".png"))
		{
			g_string_append(reply_string, "Content-type: image/png\r\n");
			if (!g_str_equal(request->filename, "/buddy_icon.png"))
			{
				g_string_append(reply_string, "Cache-Control: public\r\n");
				g_string_append(reply_string, "Pragma: cache\r\n");
				g_string_append(reply_string, "Expires: Tue, 01 Oct 2020 16:00:00 GMT\r\n");
			}
		}
		else if (g_str_has_suffix(request->filename, ".js"))
		{
				g_string_append(reply_string, "Cache-Control: no-cache\r\n");
				g_string_append(reply_string, "Content-type: text/javascript; charset=utf-8\r\n");
				g_string_append(reply_string, "Pragma: No-cache\r\n");
				g_string_append(reply_string, "Expires: Tue, 01 Sep 2000 16:00:00 GMT\r\n");
		}
		else {
			g_string_append(reply_string, "Cache-Control: public\r\n");
			g_string_append(reply_string, "Pragma: cache\r\n");
			g_string_append(reply_string, "Expires: Tue, 01 Oct 2009 16:00:00 GMT\r\n");
		}
		if (g_str_has_suffix(request->filename, ".html"))
			g_string_append(reply_string, "Content-type: text/html; charset=utf-8\r\n");
		else if (g_str_has_suffix(request->filename, ".css"))
			g_string_append(reply_string, "Content-type: text/css; charset=utf-8\r\n");
			
		/* end mime type */
		g_string_append_printf(reply_string, "Content-length: %d\r\n", response_len);
		//g_string_append(reply_string, "Connection: close\r\n");
		g_string_append(reply_string, "\r\n");
		
		g_string_append_len(reply_string, response, response_len);
		g_free(response);
		
		response_len = write(output_fd, reply_string->str, reply_string->len);
		purple_debug_info("http_ft", "write len %d\n", response_len);
		
		g_string_free(reply_string, TRUE);
	} else {
		reply_string = g_string_new(NULL);
		//purple_debug_error("pidgin_juice", "Could not find resource.\n");
		g_string_append(reply_string, "HTTP/1.0 404 Not Found\r\n");
		g_string_append(reply_string, "Content-length: 14\r\n");
		//g_string_append(reply_string, "Connection: close\r\n");
		g_string_append(reply_string, "\r\nFile not found");
		write(output_fd, reply_string->str, reply_string->len);
		g_string_free(reply_string, TRUE);
	}
	
	g_hash_table_destroy($_GET);
}

static gboolean
juice_check_auth(const gchar *header_str)
{
	GHashTable *headers;
	const gchar *authorization;
	guchar *decoded_auth;
	gchar **auth_parts;
	gboolean success = FALSE;
	const gchar *username, *password;
	
	username = purple_prefs_get_string(PREF_USERNAME);
	password = purple_prefs_get_string(PREF_PASSWORD);
	if (!username || !*username || !password || !*password)
		return TRUE;
	
	headers = juice_parse_headers(header_str);
	
	authorization = g_hash_table_lookup(headers, "Authorization");
	if (authorization && *authorization)
	{
		if (g_str_has_prefix(authorization, "Basic "))
		{
			decoded_auth = purple_base64_decode(&authorization[6], NULL);
			auth_parts = g_strsplit((gchar *)decoded_auth, ":", 2);
			if (auth_parts[0] && auth_parts[1] && 
				g_str_equal(auth_parts[0], username) &&
				g_str_equal(auth_parts[1], password))
			{
				success = TRUE;
			}
			g_strfreev(auth_parts);
			g_free(decoded_auth);
		} //TODO handle Digest auth
	}
	
	g_hash_table_destroy(headers);
	
	return success;
}

static void
juice_process_http_request(const GString *request, gint output_fd)
{
	JuiceRequestObject *jro;
	
	gchar *first_line;
	gchar *headers;
	gchar *postdata;
	gchar **first_line_info;
	gchar **uri_split;
	GString *reply_string;
	
	const gchar *buffer = request->str;
	gssize len = request->len;

	const gchar *first_line_end = g_strstr_len(buffer, len, "\r\n");
	const gchar *headers_end = g_strstr_len(buffer, len, "\r\n\r\n");
	
	do //This is a bit of a cludge, but makes the code easier to follow IMO :)
	{
		if (!first_line_end || !headers_end)
			break;
		
		first_line = g_strndup(buffer, (first_line_end - buffer));
		headers = g_strndup(first_line_end + 2, (headers_end - first_line_end - 2));
		postdata = g_strndup(headers_end + 4, (len - (headers_end - buffer) - 4));
		
		purple_debug_misc("http_ft", "Got request %s\n", first_line);
		purple_debug_misc("http_ft", "Got headers %s\n", headers);
		purple_debug_misc("http_ft", "Got postdata %s\n", postdata);
		
		first_line_info = g_strsplit_set(first_line, " ", 3);
		if (first_line_info[0] == NULL)
		{
			// Invalid request
			g_free(postdata);
			g_free(headers);
			g_free(first_line);
			g_strfreev(first_line_info);
			break;
		}
#if 0
		if (headers)
		{
			if (juice_check_auth(headers) == FALSE)
			{
				reply_string = g_string_new(NULL);
				g_string_append(reply_string, "HTTP/1.1 401 Authorization Required\r\n");
				g_string_append(reply_string, "Content-length: 0\r\n");
				g_string_append(reply_string, "WWW-Authenticate: Basic realm=\"Pidgin Security\"\r\n");
				//g_string_append(reply_string, "Connection: close\r\n");
				g_string_append(reply_string, "\r\n");
				purple_debug_warning("pidgin_juice", "Did not authenticate.\n");
				len = write(output_fd, reply_string->str, reply_string->len);
				g_string_free(reply_string, TRUE);
				
				g_free(postdata);
				g_free(headers);
				g_free(first_line);
				g_strfreev(first_line_info);
				return;
			}
		}
#endif
		
		purple_debug_misc("http_ft", "Request type %s\n", first_line_info[0]);
		purple_debug_misc("http_ft", "Request URI %s\n", first_line_info[1]);
		
		uri_split = g_strsplit_set(first_line_info[1], "?", 2);
		if (uri_split[0] == NULL)
		{
			// Invalid request
			g_free(postdata);
			g_free(headers);
			g_free(first_line);
			g_strfreev(uri_split);
			g_strfreev(first_line_info);
			break;
		}
		purple_debug_misc("http_ft", "Filename %s\n", uri_split[0]);
		purple_debug_misc("http_ft", "Query %s\n", uri_split[1]);
		
		jro = g_new0(JuiceRequestObject, 1);
		jro->first_line = first_line;
		jro->headers = headers;
		jro->postdata = postdata;
		jro->request_type = first_line_info[0];
		jro->uri = first_line_info[1];
		jro->filename = uri_split[0];
		jro->query = uri_split[1];
		
		//Handle request
		juice_handle_request(jro, output_fd);
		
		g_free(jro);
		
		g_strfreev(uri_split);
		g_strfreev(first_line_info);
		
		g_free(postdata);
		g_free(headers);
		g_free(first_line);

		return;
	} while (FALSE);
	
	reply_string = g_string_new(NULL);
	g_string_append(reply_string, "HTTP/1.1 400 Bad Request\r\n");
	g_string_append(reply_string, "Content-length: 0\r\n");
	//g_string_append(reply_string, "Connection: close\r\n");
	g_string_append(reply_string, "\r\n");
	purple_debug_info("http_ft", "Bad request. Ignoring.\n");
	len = write(output_fd, reply_string->str, reply_string->len);
	g_string_free(reply_string, TRUE);
}

static void
juice_http_read(gpointer data, gint source, PurpleInputCondition cond)
{
	char buffer[1024];
	int len;
	JuiceHandles *handles = data;

	memset(buffer, 0, sizeof(buffer));
	//TODO purple_ssl_read
	len = recv(source, buffer, sizeof(buffer), 0);

	if (len <= 0 && (errno == EAGAIN))// || errno == EWOULDBLOCK || errno == EINTR
		return;
	else if (len < 0) {
		if (handles->http_input_handle)
			purple_input_remove(handles->http_input_handle);
		close(source);
		
		purple_debug_info("http_ft", "Closed connection (%d)\n", errno);
		
		g_string_free(handles->databuffer, TRUE);
		g_free(handles);
		
		return;
	}
	
	g_string_append_len(handles->databuffer, buffer, len);
	
	if (len < sizeof(buffer)) {
		if (handles->databuffer->len > 0)
		{
			juice_process_http_request(handles->databuffer, source);
			g_string_truncate(handles->databuffer, 0);
		} else {
			if (handles->http_input_handle)
				purple_input_remove(handles->http_input_handle);
			close(source);
			
			purple_debug_info("http_ft", "Closed connection\n");
		
			g_string_free(handles->databuffer, TRUE);
			g_free(handles);
			
			return;
		}
	}
}

static void
juice_read_listen_input(gpointer data, gint source, PurpleInputCondition cond)
{
	gint flags;
	JuiceHandles *handles;

	gint acceptfd = accept(listenfd, NULL, 0);
	if (acceptfd == -1)
	{
		/* Accepting the connection failed. This could just be related
		 * to the nonblocking nature of the listening socket, so we'll
		 * just try again next time */
		/* Let's print an error message anyway */
		purple_debug_warning("http_ft", "accept: %s\n", g_strerror(errno));
		return;
	}
	
	
	flags = fcntl(acceptfd, F_GETFL);
	fcntl(acceptfd, F_SETFL, flags | O_NONBLOCK);
#ifndef _WIN32
	fcntl(acceptfd, F_SETFD, FD_CLOEXEC);
#endif

	handles = g_new0(JuiceHandles, 1);
	handles->acceptfd = acceptfd;
	handles->databuffer = g_string_new(NULL);
	
	handles->http_input_handle = purple_input_add(acceptfd, PURPLE_INPUT_READ, juice_http_read, handles);
}

static void
juice_listen_callback(int fd, gpointer data)
{
	listenfd = fd;
	input_handle = purple_input_add(listenfd, PURPLE_INPUT_READ, juice_read_listen_input, data);
}

static gchar *
juice_utf8_json_encode(const gchar *str)
{
	GString *out;
	gunichar wc;
	
	out = g_string_new(NULL);
	
	for (; *str; str = g_utf8_next_char(str))
	{
		wc = g_utf8_get_char(str);
		
		if (wc == '"' || wc == '/' || wc == '\\')
		{
			g_string_append_c(out, '\\');
			g_string_append_unichar(out, wc);
		}
		else if (wc == '\t')
		{
			g_string_append(out, "\\t");
		}
		else if (wc == '\r')
		{
			g_string_append(out, "\\r");
		}
		else if (wc == '\n')
		{
			g_string_append(out, "\\n");
		}
		else if (wc == '\f')
		{
			g_string_append(out, "\\f");
		}
		else if (wc == '\b')
		{
			g_string_append(out, "\\b");
		}
		else if (wc >= 0x80 || wc < 0x20)
		{
			g_string_append_printf(out, "\\u%04X", (guint16)wc);
		}
		else
		{
			g_string_append_unichar(out, wc);
		}
	}
	return g_string_free(out, FALSE);
}

static PurplePluginPrefFrame *
get_plugin_pref_frame(PurplePlugin *plugin) {
	PurplePluginPrefFrame *frame;
	PurplePluginPref *pref;

	frame = purple_plugin_pref_frame_new();

	pref = purple_plugin_pref_new_with_name(PREF_PORT);
	purple_plugin_pref_set_label(pref, _("Listening port"));
	purple_plugin_pref_set_bounds(pref, 80, 65534);
	purple_plugin_pref_frame_add(frame, pref);
	
	pref = purple_plugin_pref_new_with_name(PREF_USERNAME);
	purple_plugin_pref_set_label(pref, _("Username"));
	purple_plugin_pref_frame_add(frame, pref);
	
	pref = purple_plugin_pref_new_with_name(PREF_PASSWORD);
	purple_plugin_pref_set_label(pref, _("Password"));
	purple_plugin_pref_frame_add(frame, pref);

	return frame;
}

static void
choose_file_ok_cb(void *user_data, const char *filename)
{
	PurpleBlistNode *node = user_data;
	PurpleConversation *conv = NULL;
	
	gchar *basename;
	gchar *resource;
	gchar *full_url;
	
    if (PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		PurpleBuddy *buddy = (PurpleBuddy *)node;
		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, buddy->name, buddy->account);
		if (conv == NULL) {
			conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, buddy->account, buddy->name);
			purple_conversation_present(conv);
		}
	} else if (PURPLE_BLIST_NODE_IS_CHAT(node)) {
		PurpleChat *chat = (PurpleChat *)node;
		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, purple_chat_get_name(chat), chat->account);
		if (conv == NULL) {
			conv = purple_conversation_new(PURPLE_CONV_TYPE_CHAT, chat->account, purple_chat_get_name(chat));
			purple_conversation_present(conv);
		}
	}
	
	basename = g_path_get_basename(filename);
	resource = g_strdup_printf("/%d/%s", g_random_int(), purple_url_encode(basename));
	full_url = g_strdup_printf("http://%s:%d%s", purple_network_get_my_ip(listenfd), purple_network_get_port_from_fd(listenfd), resource);
	
	purple_debug_info("http_ft", "Mapping %s to %s\n", filename, resource);
	g_hash_table_insert(mapped_files, g_strdup(resource), g_strdup(filename));
	juice_add_resource_handler(resource, random_url_resource_handler);
	
	if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT) {
		purple_conv_chat_send(PURPLE_CONV_CHAT(conv), full_url);
	} else {
		purple_conv_im_send(PURPLE_CONV_IM(conv), full_url);
	}
	
	g_free(full_url);
	g_free(resource);
	g_free(basename);
}

static void
buddy_context_menu_send_file(PurpleBlistNode *node, PurplePlugin *plugin)
{
	PurpleAccount *account = NULL;
	const gchar *buddyname = NULL;
	PurpleConversation *conv = NULL;
	
    if (PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		PurpleBuddy *buddy = (PurpleBuddy *)node;
		buddyname = buddy->name;
		account = buddy->account;
		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, buddyname, account);
	} else if (PURPLE_BLIST_NODE_IS_CHAT(node)) {
		PurpleChat *chat = (PurpleChat *)node;
		account = chat->account;
		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, purple_chat_get_name(chat), account);
	}
	
	purple_request_file(plugin, _("Send file..."), NULL, FALSE,
					  G_CALLBACK(choose_file_ok_cb),
					  NULL,//G_CALLBACK(choose_file_cancel_cb),
					  account, buddyname, conv, node);
}

static void
buddy_context_menu_add_item (PurpleBlistNode *node, GList **menu, PurplePlugin *plugin)
{
	PurpleMenuAction *action;

	action = purple_menu_action_new("Send file via web", PURPLE_CALLBACK(buddy_context_menu_send_file), plugin, NULL);
	(*menu) = g_list_prepend (*menu, action);
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	gint port;
	
	port = purple_prefs_get_int(PREF_PORT);
	if (port > 0)
	{
		listen_data = purple_network_listen_range_family(port, port+10, AF_INET, SOCK_STREAM, juice_listen_callback, NULL);		
		if (listen_data == NULL)
		{
			gchar *port_error_msg = g_strdup_printf("Unable to listen on port %d\n", port);
			purple_notify_error(plugin, "Error opening port", port_error_msg, "Try changing the port number in preferences");
			g_free(port_error_msg);
		}
	}
		
	purple_signal_connect(purple_blist_get_handle(), "blist-node-extended-menu", plugin, PURPLE_CALLBACK(buddy_context_menu_add_item), plugin);
	
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	if (listen_data) {
		//purple_network_listen_cancel(listen_data);
	}
	listen_data = NULL;
	
	purple_input_remove(input_handle);
	input_handle = 0;
	
	close(listenfd);
	listenfd = -1;
	
	return TRUE;
}

static PurplePluginUiInfo prefs_info = {
	get_plugin_pref_frame,
	0,    /* page_num (Reserved) */
	NULL, /* frame (Reserved) */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};


static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	2,//PURPLE_MAJOR_VERSION,
	7,//PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,   /**< type */
	NULL,                   /**< ui_requirement */
	0,                      /**< flags */
	NULL,                   /**< dependencies */
	PURPLE_PRIORITY_DEFAULT,  /**< priority */

	"pidgin-http-ft",         /**< id */
	"HTTP File Transfers",         /**< name */
	"0.2",                  /**< version */
	"Provides filetransfers via HTTP",          /**< summary */
	"Access Pidgin remotely", /**< description */
	"Eion Robb", /**< author */
	"", /**< homepage */

	plugin_load,            /**< load */
	plugin_unload,          /**< unload */
	NULL,                   /**< destroy */

	NULL,                   /**< ui_info */
	NULL,                   /**< extra_info */
	&prefs_info,            /**< prefs_info */
	NULL,                   /**< actions */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
	purple_prefs_add_none(PREFS_BASE);
	purple_prefs_add_int(PREF_PORT, 18069);
	purple_prefs_add_string(PREF_USERNAME, "");
	purple_prefs_add_string(PREF_PASSWORD, "");
	
	resource_handlers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	mapped_files = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}


PURPLE_INIT_PLUGIN(http_ft, init_plugin, info);
