#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "sleeplock.h"
#include "fs.h"
#include "fcntl.h"
#include "file.h"

struct cpu cpus[NCPU];

struct proc proc[NPROC];

struct proc *initproc;

struct {
  struct file *file;
  int refcount;
  uint64 vatopa[(MAXFILE*BSIZE)/PGSIZE];
} vmaglobals[NFILE];
struct spinlock vmaglobal_lock;

int nextpid = 1;
struct spinlock pid_lock;

extern void forkret(void);
static void freeproc(struct proc *p);
static int mmap_vmaglobalfilei(struct file *file);

extern char trampoline[]; // trampoline.S
                          
// helps ensure that wakeups of wait()ing
// parents are not lost. helps obey the
// memory model when using p->parent.
// must be acquired before any p->lock.
struct spinlock wait_lock;

// Allocate a page for each process's kernel stack.
// Map it high in memory, followed by an invalid
// guard page.
void
proc_mapstacks(pagetable_t kpgtbl)
{
  struct proc *p;
  
  for(p = proc; p < &proc[NPROC]; p++) {
    char *pa = kalloc();
    if(pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int) (p - proc));
    kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  }
}

// initialize the proc table.
void
procinit(void)
{
  struct proc *p;
  
  initlock(&pid_lock, "nextpid");
  initlock(&wait_lock, "wait_lock");
  for(p = proc; p < &proc[NPROC]; p++) {
      initlock(&p->lock, "proc");
      p->state = UNUSED;
      p->kstack = KSTACK((int) (p - proc));
  }
}

// Must be called with interrupts disabled,
// to prevent race with process being moved
// to a different CPU.
int
cpuid()
{
  int id = r_tp();
  return id;
}

// Return this CPU's cpu struct.
// Interrupts must be disabled.
struct cpu*
mycpu(void)
{
  int id = cpuid();
  struct cpu *c = &cpus[id];
  return c;
}

// Return the current struct proc *, or zero if none.
struct proc*
myproc(void)
{
  push_off();
  struct cpu *c = mycpu();
  struct proc *p = c->proc;
  pop_off();
  return p;
}

int
allocpid()
{
  int pid;
  
  acquire(&pid_lock);
  pid = nextpid;
  nextpid = nextpid + 1;
  release(&pid_lock);

  return pid;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, or a memory allocation fails, return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    acquire(&p->lock);
    if(p->state == UNUSED) {
      goto found;
    } else {
      release(&p->lock);
    }
  }
  return 0;

found:
  p->pid = allocpid();
  p->state = USED;

  // Allocate a trapframe page.
  if((p->trapframe = (struct trapframe *)kalloc()) == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  if(p->pagetable == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context));
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;

  return p;
}

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if(p->trapframe)
    kfree((void*)p->trapframe);
  p->trapframe = 0;
  if(p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
}

// Create a user page table for a given process, with no user memory,
// but with trampoline and trapframe pages.
pagetable_t
proc_pagetable(struct proc *p)
{
  pagetable_t pagetable;

  // An empty page table.
  pagetable = uvmcreate();
  if(pagetable == 0)
    return 0;

  // map the trampoline code (for system call return)
  // at the highest user virtual address.
  // only the supervisor uses it, on the way
  // to/from user space, so not PTE_U.
  if(mappages(pagetable, TRAMPOLINE, PGSIZE,
              (uint64)trampoline, PTE_R | PTE_X) < 0){
    uvmfree(pagetable, 0);
    return 0;
  }

  // map the trapframe page just below the trampoline page, for
  // trampoline.S.
  if(mappages(pagetable, TRAPFRAME, PGSIZE,
              (uint64)(p->trapframe), PTE_R | PTE_W) < 0){
    uvmunmap(pagetable, TRAMPOLINE, 1, 0);
    uvmfree(pagetable, 0);
    return 0;
  }

  return pagetable;
}

// Free a process's page table, and free the
// physical memory it refers to.
void
proc_freepagetable(pagetable_t pagetable, uint64 sz)
{
  uvmunmap(pagetable, TRAMPOLINE, 1, 0);
  uvmunmap(pagetable, TRAPFRAME, 1, 0);
  uvmfree(pagetable, sz);
}

// a user program that calls exec("/init")
// assembled from ../user/initcode.S
// od -t xC ../user/initcode
uchar initcode[] = {
  0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x45, 0x02,
  0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x35, 0x02,
  0x93, 0x08, 0x70, 0x00, 0x73, 0x00, 0x00, 0x00,
  0x93, 0x08, 0x20, 0x00, 0x73, 0x00, 0x00, 0x00,
  0xef, 0xf0, 0x9f, 0xff, 0x2f, 0x69, 0x6e, 0x69,
  0x74, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

// Set up first user process.
void
userinit(void)
{
  struct proc *p;

  p = allocproc();
  initproc = p;
  
  // allocate one user page and copy initcode's instructions
  // and data into it.
  uvmfirst(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;      // user program counter
  p->trapframe->sp = PGSIZE;  // user stack pointer

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;

  release(&p->lock);
}

// Grow or shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint64 sz;
  struct proc *p = myproc();

  sz = p->sz;
  if(n > 0){
    if((sz = uvmalloc(p->pagetable, sz, sz + n, PTE_W)) == 0) {
      return -1;
    }
  } else if(n < 0){
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy user memory from parent to child.
  if(uvmcopy(p->pagetable, np->pagetable, p->sz) < 0){
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for(i = 0; i < NOFILE; i++)
    if(p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  for (int i = 0; i < VMASIZE; i++){
    if (p->vma[i].len){
      np->vma[i] = p->vma[i];

      if (p->vma[i].file)
        np->vma[i].file = filedup(p->vma[i].file);

      if (p->vma[i].flags == MAP_SHARED){
        int index = mmap_vmaglobalfilei(p->vma[i].file);
        if (index == -1)
          panic("FORK: can't find shared file\n");
        vmaglobals[index].refcount += 1;
      }
    }
  }

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  release(&np->lock);

  acquire(&wait_lock);
  np->parent = p;
  release(&wait_lock);

  acquire(&np->lock);
  np->state = RUNNABLE;
  release(&np->lock);

  return pid;
}

// Pass p's abandoned children to init.
// Caller must hold wait_lock.
void
reparent(struct proc *p)
{
  struct proc *pp;

  for(pp = proc; pp < &proc[NPROC]; pp++){
    if(pp->parent == p){
      pp->parent = initproc;
      wakeup(initproc);
    }
  }
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait().
void
exit(int status)
{
  struct proc *p = myproc();

  if(p == initproc)
    panic("init exiting");

  // Close all open files.
  for(int fd = 0; fd < NOFILE; fd++){
    if(p->ofile[fd]){
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  // unmap the process mapped region
  for (int i = 0; i < VMASIZE; i++){
     if (p->vma[i].len){
      procvmremove(p->vma[i].addr, p->vma[i].len);
     }
  }

  begin_op();
  iput(p->cwd);
  end_op();
  p->cwd = 0;

  acquire(&wait_lock);

  // Give any children to init.
  reparent(p);

  // Parent might be sleeping in wait().
  wakeup(p->parent);
  
  acquire(&p->lock);

  p->xstate = status;
  p->state = ZOMBIE;

  release(&wait_lock);

  // Jump into the scheduler, never to return.
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(uint64 addr)
{
  struct proc *pp;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(pp = proc; pp < &proc[NPROC]; pp++){
      if(pp->parent == p){
        // make sure the child isn't still in exit() or swtch().
        acquire(&pp->lock);

        havekids = 1;
        if(pp->state == ZOMBIE){
          // Found one.
          pid = pp->pid;
          if(addr != 0 && copyout(p->pagetable, addr, (char *)&pp->xstate,
                                  sizeof(pp->xstate)) < 0) {
            release(&pp->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(pp);
          release(&pp->lock);
          release(&wait_lock);
          return pid;
        }
        release(&pp->lock);
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || killed(p)){
      release(&wait_lock);
      return -1;
    }
    
    // Wait for a child to exit.
    sleep(p, &wait_lock);  //DOC: wait-sleep
  }
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();

  c->proc = 0;
  for(;;){
    // The most recent process to run may have had interrupts
    // turned off; enable them to avoid a deadlock if all
    // processes are waiting.
    intr_on();

    for(p = proc; p < &proc[NPROC]; p++) {
      acquire(&p->lock);
      if(p->state == RUNNABLE) {
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
        p->state = RUNNING;
        c->proc = p;
        swtch(&c->context, &p->context);

        // Process is done running for now.
        // It should have changed its p->state before coming back.
        c->proc = 0;
      }
      release(&p->lock);
    }
  }
}

// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&p->lock))
    panic("sched p->lock");
  if(mycpu()->noff != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(intr_get())
    panic("sched interruptible");

  intena = mycpu()->intena;
  swtch(&p->context, &mycpu()->context);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  struct proc *p = myproc();
  acquire(&p->lock);
  p->state = RUNNABLE;
  sched();
  release(&p->lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch to forkret.
void
forkret(void)
{
  static int first = 1;

  // Still holding p->lock from scheduler.
  release(&myproc()->lock);

  if (first) {
    // File system initialization must be run in the context of a
    // regular process (e.g., because it calls sleep), and thus cannot
    // be run from main().
    fsinit(ROOTDEV);

    first = 0;
    // ensure other cores see first=0.
    __sync_synchronize();
  }

  usertrapret();
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  // Must acquire p->lock in order to
  // change p->state and then call sched.
  // Once we hold p->lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup locks p->lock),
  // so it's okay to release lk.

  acquire(&p->lock);  //DOC: sleeplock1
  release(lk);

  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  release(&p->lock);
  acquire(lk);
}

// Wake up all processes sleeping on chan.
// Must be called without any p->lock.
void
wakeup(void *chan)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    if(p != myproc()){
      acquire(&p->lock);
      if(p->state == SLEEPING && p->chan == chan) {
        p->state = RUNNABLE;
      }
      release(&p->lock);
    }
  }
}

// Kill the process with the given pid.
// The victim won't exit until it tries to return
// to user space (see usertrap() in trap.c).
int
kill(int pid)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++){
    acquire(&p->lock);
    if(p->pid == pid){
      p->killed = 1;
      if(p->state == SLEEPING){
        // Wake process from sleep().
        p->state = RUNNABLE;
      }
      release(&p->lock);
      return 0;
    }
    release(&p->lock);
  }
  return -1;
}

void
setkilled(struct proc *p)
{
  acquire(&p->lock);
  p->killed = 1;
  release(&p->lock);
}

int
killed(struct proc *p)
{
  int k;
  
  acquire(&p->lock);
  k = p->killed;
  release(&p->lock);
  return k;
}

// Copy to either a user address, or kernel address,
// depending on usr_dst.
// Returns 0 on success, -1 on error.
int
either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  struct proc *p = myproc();
  if(user_dst){
    return copyout(p->pagetable, dst, src, len);
  } else {
    memmove((char *)dst, src, len);
    return 0;
  }
}

// Copy from either a user address, or kernel address,
// depending on usr_src.
// Returns 0 on success, -1 on error.
int
either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  struct proc *p = myproc();
  if(user_src){
    return copyin(p->pagetable, dst, src, len);
  } else {
    memmove(dst, (char*)src, len);
    return 0;
  }
}

// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [USED]      "used",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  struct proc *p;
  char *state;

  printf("\n");
  for(p = proc; p < &proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    printf("%d %s %s", p->pid, state, p->name);
    printf("\n");
  }
}

static int 
findvmai(struct proc *p, uint64 va)
{
   uint64 page_start, vmastart, vmaend;

   page_start = PGROUNDDOWN(va);

   for (int i = 0; i < VMASIZE; i++){
       if (p->vma[i].len == 0)
         continue;
       vmastart = (uint64) p->vma[i].addr; 
       vmaend = (uint64) p->vma[i].addr + p->vma[i].len;

       if (page_start >= vmastart && page_start < vmaend)
         return i;
   }
   return -1;
}

static int
mmap_vmaglobalfreei()
{
  acquire(&vmaglobal_lock); 
  for (int i =0; i < NFILE; i++){
    if (!vmaglobals[i].file){
      release(&vmaglobal_lock);
      return i;
    }
  }
  release(&vmaglobal_lock);
  return -1;
};

static int
mmap_vmaglobalfilei(struct file *f)
{
  acquire(&vmaglobal_lock); 
  for (int i =0; i < NFILE; i++){
    if (vmaglobals[i].file == f){
      release(&vmaglobal_lock);
      return i;
    }
  }
  release(&vmaglobal_lock);
  return -1;
};

static uint64
mmap_vmaglobalfilepageindex(struct vma *vma, uint64 va)
{
  uint64 va_offset_with_mapping = va - (uint64)vma->addr;
  int file_position = vma->offset + va_offset_with_mapping;
  int index = file_position / PGSIZE;
  return index;
};

static int
mmap_read(struct file *file, uint64 pa, int offset)
{
  if (file) {
    begin_op();
    ilock(file->ip);
    int n = readi(file->ip, 0, (uint64)pa, offset, PGSIZE);
    if (n < 0){ 
      iunlock(file->ip);
      end_op();
      return -1;
    }
    if (n < PGSIZE){
      memset((char*)(pa + n),0,PGSIZE-n);
    }
    iunlock(file->ip);
    end_op();
    return 0;
  }
  return -1;
}

static int
mmap_copy_shared_page(struct proc *p, int vmaindex, uint64 va)
{
  int vmaglobali = mmap_vmaglobalfilei(p->vma[vmaindex].file);
  if (vmaglobali == -1)
    return -1;
  int pageindex = mmap_vmaglobalfilepageindex(&p->vma[vmaindex], va);
  int pa = vmaglobals[vmaglobali].vatopa[pageindex];
  if (!pa)
    return -1;
  int flags = ((p->vma[vmaindex].prot & PROT_READ) ? PTE_R : 0) | ((p->vma[vmaindex].prot & PROT_WRITE) ? PTE_W : 0);
  if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, PTE_U|flags)) {
    return -1;
  }
  printf("SHARED: physical %p va %p\n", pa, va);
  return 0;
}

static int
mmap_copy_private_page(struct proc *p, uint64 va)
{
  char *mem;
  acquire(&wait_lock);
  struct proc *parent = p->parent;
  pte_t *pte = walk(parent->pagetable, va, 0);
  if (!pte){
    release(&wait_lock);
    return -1;
  }
  uint64 pa = PTE2PA(*pte);
  if (!pa){
    release(&wait_lock);
    return -1;
  }
  mem = kalloc();
  if (mem == 0){
    release(&wait_lock);
    return -1;
  }
  memmove(mem, (char*) pa, PGSIZE);
  if (mappages(p->pagetable, va, PGSIZE, (uint64)mem, PTE_FLAGS(*pte)) != 0){
    release(&wait_lock);
    kfree(mem);
    return -1;
  }
  release(&wait_lock);
  printf("PAGE FAULT: copying private page from parent\n");
  return 0;
}

// Return 0 if handled 
int
vmapagefaulthandler(uint64 va)
{
  struct proc *p = myproc();
  struct vma vma;
  uint64 faulting_va, page_start;
  char *pa;
  
  faulting_va = PGROUNDDOWN(va);
  int vmaindex = findvmai(p, faulting_va);
  if (vmaindex == -1)
    return -1;
  page_start = (uint64)p->vma[vmaindex].addr;
  vma = p->vma[vmaindex];

  printf("PAGE FAULT: start %p pid %d addr %p  len %d  vmaindex %d prot %d offset %d flags %d\n", vma.addr, p->pid, page_start ,PGSIZE, vmaindex, vma.prot, vma.offset, vma.flags);

  if (vma.flags == MAP_SHARED && (mmap_copy_shared_page(p, vmaindex, faulting_va) != -1)){
    return 0;
  }
  if (vma.flags == MAP_PRIVATE && (mmap_copy_private_page(p, faulting_va) != -1)){
    return 0;
  }

  pa = kalloc();
  if (!pa)
    panic("PAGE FAULT: kalloc");
  memset(pa, 0, PGSIZE);

  int offset = vma.offset + (faulting_va - page_start);
  if (mmap_read(vma.file,(uint64) pa,offset) == -1){
      uvmunmap(p->pagetable, page_start, 1, 1);
      return -1;
  }

  int flags = ((vma.prot & PROT_READ) ? PTE_R : 0) | ((vma.prot & PROT_WRITE) ? PTE_W : 0);
  if (mappages(p->pagetable, faulting_va, PGSIZE, (uint64)pa, PTE_U|flags) != 0){
    kfree(pa);
    return -1;
  }

  if (vma.flags == MAP_SHARED){
    int index = mmap_vmaglobalfilei(p->vma[vmaindex].file);
    if (index == -1)
      panic("PAGE FAULT: shared file not found\n");
    int pageindex = mmap_vmaglobalfilepageindex(&p->vma[vmaindex], faulting_va);
    vmaglobals[index].vatopa[pageindex] = (uint64)pa;
    printf("PAGE FAULT: MAP SHARED UPDATED pa %p for va %p PTE_R %d PTE_W %d\n", pa, faulting_va, flags & PTE_R, flags & PTE_W);
  }

  return 0;
}

// Remove mapped region
int 
procvmremove(void *addr, int len)
{
  struct proc *p = myproc(); 
  struct vma vma;
  uint64 page_start, vmastart;
  int vmalen;

  page_start = PGROUNDDOWN((uint64)addr);
  int vmaindex = findvmai(p, (uint64) addr);
  if (vmaindex == -1)
    return -1;
  vma = p->vma[vmaindex]; 
  vmastart = (uint64)vma.addr; 
  vmalen = vma.len;
  printf("START UNMAP: [%p,%d] addr %p pid %d len %d vmaindex %d prot %d offset %d flags %d\n", vmastart, vmalen, addr, p->pid, len, vmaindex, vma.prot, vma.offset, vma.flags); 

  if (vma.file) {
    struct inode * ip = vma.file->ip; 
    begin_op();
    ilock(ip);
    for (int i=0; i<len; i+=PGSIZE){
      uint64 page_addr = page_start + i;
      pte_t *pte = walk(p->pagetable, page_start + i, 0); 
      uint64 pa = PTE2PA(*pte);
      if (pte && (*pte & PTE_V)){
        if (vma.flags & MAP_SHARED){
          printf("Writing at pa %p and offset %p PTE_W %d PTE_R %d\n", pa, vma.offset + i, *pte & PTE_W,*pte & PTE_R);
          writei(ip, 0, pa, vma.offset + i, PGSIZE);
        }
        uvmunmap(p->pagetable, page_addr, 1, 0);
      }
    }
    iunlock(ip);
    end_op();
  }

  if (vmastart == page_start){
    if (len >= vmalen) {
      int fileindex = mmap_vmaglobalfilei(vma.file);
      vmaglobals[fileindex].refcount -= 1;
      if (vmaglobals[fileindex].refcount <= 0){
        memset(&vmaglobals[fileindex], 0, sizeof(vmaglobals[0]));
      }
      fileclose(vma.file);
      memset(&p->vma[vmaindex], 0, sizeof(struct vma));
    } else {
      p->vma[vmaindex].addr = (void*)(page_start + len); 
      p->vma[vmaindex].len -= len;
    }
  } else if (page_start + len == vmastart + vmalen) {
    p->vma[vmaindex].len = page_start - vmastart;
  } else {
    // Splitting VMA 
    int newvma = -1;
    for (int i = 0 ; i < VMASIZE; i++){
      if (p->vma[i].len == 0){
        newvma = i;
        break;
      }
    }
    if (newvma == -1)
      return -1; // No free VMA slot

    p->vma[newvma] = (struct vma)  {(void *)(page_start + len),vmalen-(page_start + len - vmastart),vma.prot,vma.flags,(struct file *)filedup(vma.file),vma.offset + (page_start + len - vmastart)};
    p->vma[vmaindex].len = page_start - vmastart;
  }

  printf("DONE UNMAP: addr %p len %d\n", p->vma[vmaindex].addr, p->vma[vmaindex].len);
  return 0;
}

// Add mapped region
void*
procvmaadd(int len, int prot, int flags, int fd, int offset)
{
  struct proc *p = myproc();
  uint64 start,top = MAXVA - (2 * PGSIZE); // account for trampoline and trapframe
  int count = PGSIZE;

  struct file * file = p->ofile[fd];

  if ((file->readable == 0) && (prot & PROT_READ))
    return (void *) -1;
  if ((file->writable == 0) && (prot & PROT_WRITE) && ((flags & MAP_PRIVATE) == 0))
    return (void *) -1;
  if ((len % PGSIZE) != 0 || fd < 0 || fd >= NOFILE || p->ofile[fd] == 0)
    return (void*) -1;

  while (top > p->sz){
     start = top - count; // Calculate start based on accumulated count

     int found = 1;
     for (int i = 0; i < VMASIZE; i++){
       if (p->vma[i].len == 0){
         continue;
       }
       uint64 vmastart = (uint64) p->vma[i].addr;
       uint64 vmaend = vmastart + p->vma[i].len;
       if (start < vmaend && top > vmastart){
         found = 0;
         count = 0;
         top = vmastart;
         break;
       }
     }

     if (found && count >= len){
         int j = 0;
         while (p->vma[j].len != 0 && j < VMASIZE)
           j++;
         if (j == VMASIZE)
           return (void *) -1;
         printf("MMAP: addr %p pid %d len %d vmaindex %d prot %d offset %d flags %d\n", start, p->pid, len, j, prot, offset, flags);
         p->vma[j] = (struct vma)  {(void *)start,len,prot,flags,(struct file *)filedup(p->ofile[fd]),offset};
         int index = mmap_vmaglobalfilei(file);
         if (index == -1){
           index = mmap_vmaglobalfreei(); 
           if (index == -1){
             panic("MMAP: shared vma full\n");
           }
           vmaglobals[index].refcount = 1;
           vmaglobals[index].file = file;
         }
         else {
           vmaglobals[index].refcount += 1;
         }

         return (void *) start;
     }

     count += PGSIZE;
  }
  
  return (void*) -1;
}
