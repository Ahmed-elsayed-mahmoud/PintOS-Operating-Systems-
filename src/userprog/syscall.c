#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

typedef int pid_t;

#define USER_VADDR_BOTTOM ((void *) 0x08048000)
#define MAX_ARGS 3

struct lock filesys_lock;
static void syscall_handler (struct intr_frame *);
int process_add_file (struct file *f);
struct process_file* process_get_file (int fd);
void check_valid_ptr (const void *vaddr);
void get_arg(void* vaddr, int argv[], int argc);


void
syscall_init (void)
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{


	check_valid_ptr((const void*) f->esp);
	/* esp points to the last element on stack */
	void* ptr = f->esp;
	/*first element in the stack is the System Call Number*/
	int system_call_number = *((int*) ptr);
	ptr +=4;
	check_valid_ptr((const void*) ptr);
	/*max number of argumnets in all syscall methods is = 3*/
	int argv[3];


	switch (system_call_number) {
	case SYS_HALT: {
		halt();
		break;
	}
	case SYS_EXIT: {
		get_arg(ptr, argv, 1);
		exit(argv[0]);
		break;
	}
	case SYS_EXEC: {
		get_arg(ptr, argv, 1);
		check_valid_ptr((const void*) argv[0]);
		f->eax = exec((const char*) argv[0]);
		break;
	}
	case SYS_WAIT: {
		get_arg(ptr, argv, 1);
		f->eax = wait(argv[0]);
		break;
	}
	case SYS_CREATE: {
		get_arg(ptr, argv, 2);
		check_valid_ptr((const void*) argv[0]);
		f->eax = create((const char*) argv[0], (unsigned)argv[1]);
		break;
	}
	case SYS_REMOVE: {
		get_arg(ptr, argv, 1);
		check_valid_ptr((const void*) argv[0]);
		f->eax = remove((const char*) argv[0]);
		break;
	}
	case SYS_OPEN: {
		get_arg(ptr, argv, 1);
		check_valid_ptr((const void*) argv[0]);
		f->eax = open((const char*)argv[0]);
		break;
	}
	case SYS_FILESIZE: {
		get_arg(ptr, argv, 1);
		f->eax = filesize(argv[0]);
		break;
	}
	case SYS_READ: {
		get_arg(ptr, argv, 3);
		check_valid_ptr((const void*) argv[1]);
		void* buff = ((void*) argv[1])+ argv[2];
		check_valid_ptr((const void*) buff);
		f->eax = read(argv[0], (void*)argv[1], (unsigned)argv[2]);
		break;
	}
	case SYS_WRITE: {
		get_arg(ptr, argv, 3);
		check_valid_ptr((const void*) argv[1]);
		void* buff = ((void*) argv[1])+ argv[2];
		check_valid_ptr((const void*) buff);
		f->eax = write(argv[0], (void*)argv[1], (unsigned)argv[2]);
		break;
	}
	case SYS_SEEK: {
		get_arg(ptr, argv, 2);
		seek(argv[0], (unsigned)argv[1]);
		break;
	}
	case SYS_TELL: {
		get_arg(ptr, argv, 1);
		f->eax = tell(argv[0]);
		break;
	}
	case SYS_CLOSE: {
		get_arg(ptr, argv, 1);
		close(argv[0]);
		break;
	}
	default: {
		printf("INVALID system call!\n");
		exit(ERROR);
		break;
	}
    }
}

void halt (void)
{
  shutdown_power_off();
}


void exit(int status)
{
    struct thread *cur = thread_current();

    cur->child_status = status;

    struct killed_thread *kt = malloc(sizeof(struct killed_thread));
    kt->tid = cur->tid;
    kt->status = status;
    kt->wait = cur->wait;

    struct thread* p = get_thread(cur->parent);
    if (p != NULL)
    {
	 list_push_back(&p->killed_child, &kt->elem);
    }

    printf("%s: exit(%d)\n", thread_current()->name, status);

    thread_exit();
}


pid_t exec (const char *cmd_line)
{
    pid_t pid = -1;
    pid = process_execute(cmd_line);
    if (pid == LOAD_FAIL)
    {
	return ERROR;
    }
    return pid;
}

int wait (pid_t pid)
{
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size)
{
  lock_acquire(&filesys_lock);

  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

bool remove (const char *file)
{
  lock_acquire(&filesys_lock);

  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

int open (const char *file)
{
  lock_acquire(&filesys_lock);

  struct file *f = filesys_open(file);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int fd = process_add_file(f);
  lock_release(&filesys_lock);
  return fd;
}

int filesize (int fd)
{
  lock_acquire(&filesys_lock);

  struct process_file *pf = process_get_file(fd);
  if (pf == NULL)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int size = file_length(pf->file);
  lock_release(&filesys_lock);
  return size;
}

int read (int fd, void *buffer, unsigned size)
{
  if (fd == STDIN_FILENO)
    {
      unsigned i;
      uint8_t* local_buffer = (uint8_t *) buffer;
      for (i = 0; i < size; i++)
	{
	  local_buffer[i] = input_getc();
	}
      return size;
    }

  lock_acquire(&filesys_lock);
  struct process_file *pf = process_get_file(fd);
  if (pf == NULL)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int bytes = file_read(pf->file, buffer, size);
  lock_release(&filesys_lock);
  return bytes;
}

int write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
    {
      putbuf(buffer, size);
      return size;
    }

  lock_acquire(&filesys_lock);
  struct process_file *pf = process_get_file(fd);
  if (pf == NULL)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int bytes = file_write(pf->file, buffer, size);
  lock_release(&filesys_lock);
  return bytes;
}

void seek (int fd, unsigned position)
{
  lock_acquire(&filesys_lock);

  struct process_file *pf = process_get_file(fd);
  if (pf == NULL)
    {
      lock_release(&filesys_lock);
      return;
    }
  file_seek(pf->file, position);
  lock_release(&filesys_lock);
}

unsigned tell (int fd)
{
  lock_acquire(&filesys_lock);

  struct process_file *pf = process_get_file(fd);
  if (pf == NULL)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  off_t offset = file_tell(pf->file);
  lock_release(&filesys_lock);
  return offset;
}

void close (int fd)
{
  lock_acquire(&filesys_lock);

  process_close_file(fd);
  lock_release(&filesys_lock);
}

struct thread* get_child_process (int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->child_list); e != list_end (&t->child_list);
       e = list_next (e))
        {
          struct thread *cp = list_entry (e, struct thread, child_elem);
          if (pid == cp->tid)
	    {
	      return cp;
	    }
        }
  return NULL;
}

struct killed_thread* get_killed_thread (int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->killed_child); e != list_end (&t->killed_child);
       e = list_next (e))
        {
          struct killed_thread *kt = list_entry (e, struct killed_thread, elem);
          if (pid == kt->tid)
	    {
	      return kt;
	    }
        }
  return NULL;
}

void add_child_process (struct list_elem* elem)
{
  list_push_back(&thread_current()->child_list, elem);
}

void remove_child_process (struct thread *cp)
{
  list_remove(&cp->child_elem);
}

void remove_child_processes (void)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->child_list);

  while (e != list_end (&t->child_list))
    {
      next = list_next(e);
      struct thread *cp = list_entry (e, struct thread,
					    child_elem);
      list_remove(&cp->child_elem);
      e = next;
    }
}


void remove_killed_processes (void)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->killed_child);

  while (e != list_end (&t->killed_child))
    {
      next = list_next(e);
      struct killed_thread *kt = list_entry (e, struct killed_thread, elem);
      list_remove(&kt->elem);
      free(kt);
      e = next;
    }
}


int process_add_file (struct file *f)
{
  if (f == NULL)
  {
	return -1;
  }
  struct process_file *pf = malloc(sizeof(struct process_file));
  pf->file = f;
  pf->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->file_list, &pf->elem);
  return pf->fd;
}

struct process_file* process_get_file (int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->file_list); e != list_end (&t->file_list);
       e = list_next (e))
        {
          struct process_file *pf = list_entry (e, struct process_file, elem);
          if (fd == pf->fd)
	    {
	      return pf;
	    }
        }
  return NULL;
}

void process_close_file (int fd)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->file_list);

  while (e != list_end (&t->file_list))
    {
      next = list_next(e);
      struct process_file *pf = list_entry (e, struct process_file, elem);
      if (fd == pf->fd || fd == CLOSE_ALL)
	{
	  file_close(pf->file);
	  list_remove(&pf->elem);
        free(pf);
	  if (fd != CLOSE_ALL)
	    {
	      return;
	    }
	}
      e = next;
    }
}


void check_valid_ptr (const void *vaddr)
{
  if (!is_user_vaddr(vaddr) || vaddr < USER_VADDR_BOTTOM)
    {
      exit(ERROR);
    }

  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
    {
      exit(ERROR);
    }

}

void get_arg(void* vaddr, int argv[], int argc)
{
	int i = 0;
	while(i < argc){
		check_valid_ptr(vaddr);
		argv[i] = *((int*)vaddr);
		vaddr += 4;
		i++;
	}
}
