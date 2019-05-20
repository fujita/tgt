/*
 * Copyright(2013) Cachebox Inc.
 *
 * dll.h
 */

#ifndef DDL_H
#define DDL_H


#ifndef offsetof
#ifndef __builtin_offsetof
#define offsetof(type, member) ((size_t)(&(((type *) 0)->member)))
#else
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
	(type *) (((char *) ptr) - offsetof(type, member))
#endif

struct dllist {
	struct dllist	*dll_next;
	struct dllist	*dll_prev;
};
typedef struct dllist dll_t;

#define DLL_INIT(dllp) {	\
	(dllp)->dll_next = (dllp); \
	(dllp)->dll_prev = (dllp); \
};

#define DLL_REM(dllp) { \
	(dllp)->dll_next->dll_prev = (dllp)->dll_prev; \
	(dllp)->dll_prev->dll_next = (dllp)->dll_next; \
	(dllp)->dll_next = (dllp); \
	(dllp)->dll_prev = (dllp); \
};

#define DLL_ADD(dllp, newp) { \
	(newp)->dll_next = (dllp)->dll_next; \
	(newp)->dll_prev = (dllp); \
	(dllp)->dll_next->dll_prev = (newp); \
	(dllp)->dll_next = (newp); \
};

#define DLL_REVADD(dllp, newp) { \
	(newp)->dll_prev = (dllp)->dll_prev; \
	(newp)->dll_next = (dllp); \
	(dllp)->dll_prev = (newp); \
	(newp)->dll_prev->dll_next = (newp); \
};

#define DLL_MOVE(oldlist, newlist) do {                                 \
	if (!DLL_ISEMPTY(oldlist)) {                                    \
		dll_t *_np = (newlist)->dll_prev;                       \
		dll_t *_op = (oldlist)->dll_prev;                       \
		/* add items from oldlist to newlist */                 \
		_np->dll_next = (oldlist)->dll_next;                    \
		(oldlist)->dll_next->dll_prev = _np;                    \
		/* oldlist end should now point to newlist head */      \
		_op->dll_next = (newlist);                              \
		(newlist)->dll_prev = _op;                              \
		DLL_INIT(oldlist);                                      \
	}                                                               \
} while(0)

#define DLL_ISEMPTY(dllp) ((dllp)->dll_next == (dllp))

#define DLL_PREV(dllp)	((dllp)->dll_prev)
#define DLL_NEXT(dllp)	((dllp)->dll_next)

#endif /* DDL_H */
