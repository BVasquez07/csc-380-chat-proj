#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include "util.h"
#include "auth.h"
#include <openssl/sha.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

unsigned char session_k_enc[32]; // AES key
unsigned char session_k_mac[32]; // HMAC key


static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

// handshake() makes ephemeral keys and sends them to the other side
// and receives the other side's ephemeral key.

// It also generates the shared key material and splits it into two keys:
// one for AES encryption and one for HMAC authentication.
// The keys are stored in session_k_enc and session_k_mac.

// Once keys are used for encryption and authentication, they should be shredded
// to prevent memory leaks and to ensure that the keys are not left in memory.
// Therefore, even if network traffic is intercepted, the keys cannot be used to decrypt the data
// since keys are shredded after use.

int handshake(int sockfd, int is_client) {
    dhKey my_dh;
    initKey(&my_dh);
    dhGenk(&my_dh); 


    char my_pub_buf[2048];
    size_t pub_written = 0;
    Z2BYTES((unsigned char*)my_pub_buf, &pub_written, my_dh.PK);
    if (send(sockfd, my_pub_buf, pub_written, 0) == -1)
        error("send DH public key failed");
    unsigned char peer_pub_buf[2048];
    ssize_t received = recv(sockfd, peer_pub_buf, sizeof(peer_pub_buf), 0);
    if (received <= 0) error("recv DH public key failed");

    mpz_t peer_pk;
    mpz_init(peer_pk);
    BYTES2Z(peer_pk, peer_pub_buf, received);

    unsigned char key_material[64];
    dhFinal(my_dh.SK, my_dh.PK, peer_pk, key_material, sizeof(key_material));
    memcpy(session_k_enc, key_material, 32);      
    memcpy(session_k_mac, key_material + 32, 32);
    fprintf(stderr, " Shared AES key: ");
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", session_k_enc[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, " Shared HMAC key: ");
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", session_k_mac[i]);
    fprintf(stderr, "\n");

    unsigned char transcript[4096];
    size_t my_pub_len = 0;
    unsigned char* my_pub_bytes = Z2BYTES(NULL, &my_pub_len, my_dh.PK);
    unsigned char* peer_pub_bytes = peer_pub_buf;
    size_t peer_pub_len = received;

    SHA256_CTX sha_ctx;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_Init(&sha_ctx);

	if (mpz_cmp(my_dh.PK, peer_pk) < 0) {
		SHA256_Update(&sha_ctx, my_pub_bytes, my_pub_len);
		SHA256_Update(&sha_ctx, peer_pub_bytes, peer_pub_len);
	} else {
		SHA256_Update(&sha_ctx, peer_pub_bytes, peer_pub_len);
		SHA256_Update(&sha_ctx, my_pub_bytes, my_pub_len);
	}

	SHA256_Update(&sha_ctx, "handshake", 9);
	SHA256_Final(digest, &sha_ctx);


    unsigned char* sig = NULL;
    size_t sig_len = 0; 
    const char* my_key_file = is_client ? "client_private.pem" : "server_private.pem";
    if (sign_data(my_key_file, digest, sizeof(digest), &sig, &sig_len) != 0)
        error("Signing handshake failed");

    uint16_t net_sig_len = htons(sig_len);
    send(sockfd, &net_sig_len, sizeof(net_sig_len), 0);
    send(sockfd, sig, sig_len, 0);

    uint16_t peer_sig_len_net;
    recv(sockfd, &peer_sig_len_net, sizeof(peer_sig_len_net), MSG_WAITALL);
    size_t peer_sig_len = ntohs(peer_sig_len_net);
    unsigned char* peer_sig = malloc(peer_sig_len);
    recv(sockfd, peer_sig, peer_sig_len, MSG_WAITALL);

    const char* peer_key_file = is_client ? "server_public.pem" : "client_public.pem";
    int result = verify_signature(peer_key_file, digest, sizeof(digest), peer_sig, peer_sig_len);
    if (result != 1) error("Signature verification failed");

	fprintf(stderr, "Signature verified successfully.\n");

    free(sig);
    free(peer_sig);
    free(my_pub_bytes);
    mpz_clear(peer_pk);
    shredKey(&my_dh);

    return 0;
}


int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

static void sendMessage(GtkWidget* w, gpointer)
{
	char* tags[2] = {"self", NULL};
	tsappend("me: ", tags, 0);

	GtkTextIter mstart, mend;
	gtk_text_buffer_get_start_iter(mbuf, &mstart);
	gtk_text_buffer_get_end_iter(mbuf, &mend);
	char* message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);
	size_t utf8_len = strlen(message); // not g_utf8_strlen, just raw bytes

	// --- Generate IV ---
	unsigned char iv[16];
	if (!RAND_bytes(iv, sizeof(iv)))
		error("RAND_bytes failed");

	// --- Encrypt message ---
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	unsigned char ciphertext[512];
	int enc_len = 0, final_len = 0;

	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_k_enc, iv);
	EVP_EncryptUpdate(ctx, ciphertext, &enc_len, (unsigned char*)message, utf8_len);
	EVP_EncryptFinal_ex(ctx, ciphertext + enc_len, &final_len);
	enc_len += final_len;
	EVP_CIPHER_CTX_free(ctx);

	// --- Compute HMAC ---
	unsigned char hmac[32];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	HMAC_CTX* hctx = HMAC_CTX_new();
	HMAC_Init_ex(hctx, session_k_mac, 32, EVP_sha256(), NULL);
	HMAC_Update(hctx, iv, sizeof(iv));
	HMAC_Update(hctx, ciphertext, enc_len);
	HMAC_Final(hctx, hmac, NULL);
	HMAC_CTX_free(hctx);
#pragma GCC diagnostic pop

	// Open the log file
    FILE* log_file = fopen("chat_log.txt", "a");
    if (!log_file) {
        perror("Failed to open log file");
        return;
    }

    // Log the plaintext
    fprintf(log_file, "Plaintext: %s\n", message);

    // Log the ciphertext in hex format
    fprintf(log_file, "Ciphertext: ");
    for (int i = 0; i < enc_len; i++) {
        fprintf(log_file, "%02x", ciphertext[i]);
    }
    fprintf(log_file, "\n\n");

    fclose(log_file);

	// --- Send message: [len][iv][ciphertext][hmac] ---
	uint16_t clen_net = htons(enc_len);
	if (send(sockfd, &clen_net, sizeof(clen_net), 0) == -1 ||
	    send(sockfd, iv, sizeof(iv), 0) == -1 ||
	    send(sockfd, ciphertext, enc_len, 0) == -1 ||
	    send(sockfd, hmac, sizeof(hmac), 0) == -1)
		error("send failed");

	tsappend(message, NULL, 1);
	free(message);
	gtk_text_buffer_delete(mbuf, &mstart, &mend);
	gtk_widget_grab_focus(w);
}

static gboolean shownewmessage(gpointer msg) {
    char* tags[2] = {"friend", NULL};
    char* friendname = "mr. friend: ";
    tsappend(friendname, tags, 0);
    char* message = (char*)msg;
    tsappend(message, NULL, 1);
    free(message);
    return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}
	handshake(sockfd, isclient); // run the handshake
	// check to make sure the ephemeral key is being regen each new message!

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void*)
{
	size_t maxlen = 512;
	unsigned char iv[16];
	unsigned char ciphertext[maxlen];
	unsigned char received_hmac[32];
	unsigned char computed_hmac[32];

	uint16_t clen_net;
	ssize_t nbytes;

	while (1) {
		nbytes = recv(sockfd, &clen_net, sizeof(clen_net), MSG_WAITALL);
		if (nbytes <= 0) return 0;
		uint16_t clen = ntohs(clen_net);

		nbytes = recv(sockfd, iv, sizeof(iv), MSG_WAITALL);
		if (nbytes <= 0) return 0;

		nbytes = recv(sockfd, ciphertext, clen, MSG_WAITALL);
		if (nbytes <= 0) return 0;

		nbytes = recv(sockfd, received_hmac, sizeof(received_hmac), MSG_WAITALL);
		if (nbytes <= 0) return 0;

		// HMAC Verification
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		HMAC_CTX* hctx = HMAC_CTX_new();
		HMAC_Init_ex(hctx, session_k_mac, 32, EVP_sha256(), NULL);
		HMAC_Update(hctx, iv, sizeof(iv));
		HMAC_Update(hctx, ciphertext, clen);
		HMAC_Final(hctx, computed_hmac, NULL);
		HMAC_CTX_free(hctx);
#pragma GCC diagnostic pop

		if (memcmp(received_hmac, computed_hmac, 32) != 0) {
			fprintf(stderr, "HMAC verification failed!\n");
			continue;
		}

		// Decrypt
		unsigned char plaintext[maxlen + 1];
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		int dec_len = 0, final_len = 0;

		EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_k_enc, iv);
		EVP_DecryptUpdate(ctx, plaintext, &dec_len, ciphertext, clen);
		EVP_DecryptFinal_ex(ctx, plaintext + dec_len, &final_len);
		dec_len += final_len;
		EVP_CIPHER_CTX_free(ctx);

		plaintext[dec_len] = '\0';
		char* m = malloc(dec_len + 1);
		memcpy(m, plaintext, dec_len + 1);

		// Open the log file
        FILE* log_file = fopen("chat_log.txt", "a");
        if (!log_file) {
            perror("Failed to open log file");
            continue;
        }

        // Log the ciphertext in hex format
        fprintf(log_file, "Ciphertext: ");
        for (int i = 0; i < clen; i++) {
            fprintf(log_file, "%02x", ciphertext[i]);
        }
        fprintf(log_file, "\n");

        // Log the plaintext
        fprintf(log_file, "Plaintext: %s\n\n", plaintext);

        fclose(log_file);

		g_main_context_invoke(NULL, shownewmessage, (gpointer)m);
	}
	return 0;
}

