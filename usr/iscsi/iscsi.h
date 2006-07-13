extern int iscsi_init(int *);
extern int iscsi_poll_init(struct pollfd *);
extern int iscsi_event_handle(struct pollfd *);
extern int iscsi_target_create(int, char *);
extern int iscsi_target_destroy(int);
extern int iscsi_target_bind(int);

struct tgt_driver iscsi = {
	.name		= "iscsi",
	.init		= iscsi_init,
	.poll_init	= iscsi_poll_init,
	.event_handle	= iscsi_event_handle,
	.target_create	= iscsi_target_create,
	.target_destroy	= iscsi_target_destroy,
	.target_bind	= iscsi_target_bind,
};
