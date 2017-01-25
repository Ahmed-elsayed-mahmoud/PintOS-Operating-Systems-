#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

#define EXIT_SUCCESS 0          /* Successful execution. */
#define EXIT_FAILURE 1          /* Unsuccessful execution. */
#define ERROR -1

#define CLOSE_ALL -1

#define NOT_LOADED 0
#define LOAD_SUCCESS 1
#define LOAD_FAIL -1


void syscall_init (void);

struct thread* get_child_process (int pid);
void add_child_process (struct list_elem* elem);
void remove_child_process (struct thread *cp);
void remove_child_processes (void);
void process_close_file (int fd);

void acquire_filesys_lock(void);
void release_filesys_lock(void);

void remove_killed_processes (void);
struct killed_thread* get_killed_thread (int pid);


#endif /* userprog/syscall.h */
