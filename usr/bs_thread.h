#define NR_WORKER_THREADS	4

typedef void (request_func_t) (struct scsi_cmd *);

struct bs_thread_info {
	pthread_t ack_thread;
	pthread_t worker_thread[NR_WORKER_THREADS];

	/* protected by pipe */
	struct list_head ack_list;

	pthread_cond_t finished_cond;
	pthread_mutex_t finished_lock;
	struct list_head finished_list;

	/* wokers sleep on this and signaled by tgtd */
	pthread_cond_t pending_cond;
	/* locked by tgtd and workers */
	pthread_mutex_t pending_lock;
	/* protected by pending_lock */
	struct list_head pending_list;

	pthread_mutex_t startup_lock;

	int command_fd[2];
	int done_fd[2];

	int stop;

	request_func_t *request_fn;
};

static inline struct bs_thread_info *BS_THREAD_I(struct scsi_lu *lu)
{
	return (struct bs_thread_info *) ((char *)lu + sizeof(*lu));
}

extern int bs_thread_open(struct bs_thread_info *info, request_func_t *rfn,
			  int nr_threads);
extern void bs_thread_close(struct bs_thread_info *info);
extern int bs_thread_cmd_submit(struct scsi_cmd *cmd);

