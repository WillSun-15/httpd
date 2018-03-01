
#define MAXEVENTS	20480
#define MAX_PORCESS	20480

#define BUF_SIZE	4096

#define MAX_URL_LENGTH	128
//use port 8080 for test. Will change it to input port in future
//#define PORT 8080

#define INDEX_FILE "/index.html"

//Process is just """name""". Not the process
struct process {
    int sock;//use socket as the key of hashtable
    int status;
    int response_code;
    int fd;
    int read_pos;
    int write_pos;
    int total_length;
    char buf[BUF_SIZE];
};


void send_response_header(struct process *process);

int setNonblocking(int fd);

struct process* accept_sock(int listen_sock);

void read_request(struct process* process);

void send_response_header(struct process *process);

void send_response(struct process *process);

void cleanup(struct process *process);

void handle_error(struct process *process, char* error_string);

void reset_process(struct process *process);

int open_file(char *filename);

