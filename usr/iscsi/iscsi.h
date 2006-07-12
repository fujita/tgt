extern int iscsi_init(int *);
extern int iscsi_poll_init(struct pollfd *);
extern int iscsi_event_handle(struct pollfd *);
extern int iscsi_target_create(int, char *);
extern int iscsi_target_destroy(int);
extern int iscsi_target_bind(int);
