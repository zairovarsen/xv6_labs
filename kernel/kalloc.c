// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "riscv.h"
#include "defs.h"

void freerange(void *pa_start, void *pa_end);

extern char end[]; // first address after kernel.
                   // defined by kernel.ld.
struct run {
  struct run *next;
};

struct {
  int rc[PHYSTOP >> PGSHIFT];
  struct spinlock lock;
  struct run *freelist;
} kmem;

void
kinit()
{
  initlock(&kmem.lock, "kmem");

  for (int i =0; i < (PGROUNDUP(PHYSTOP)-KERNBASE) / PGSIZE; i++)
    kmem.rc[i] = 1;
  freerange(end, (void*)PHYSTOP);
}

int
kgetRcIndex(void *pa)
{
  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kgetRcIndex");

  uint64 pa0 = ((uint64) pa - KERNBASE);
  return pa0 >> PGSHIFT; 
}

int 
kgetrc(void *pa)
{
  int index = kgetRcIndex(pa);
  return kmem.rc[index]; 
}

void 
kincrc(void *pa)
{
  int index = kgetRcIndex(pa);
  kmem.rc[index] += 1;
}

void 
kdecrc(void *pa)
{
  int index = kgetRcIndex(pa);
  kmem.rc[index] -= 1;
}

void
freerange(void *pa_start, void *pa_end)
{
  char *p;
  p = (char*)PGROUNDUP((uint64)pa_start);
  for(; p + PGSIZE <= (char*)pa_end; p += PGSIZE)
    kfree(p);
}

// Free the page of physical memory pointed at by pa,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa)
{
  struct run *r;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  if (kgetrc(pa) <= 0)
    panic("kfree_decr\n");

  kdecrc(pa);
  if (kgetrc(pa) > 0)
    return;
  
  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);
  r = (struct run*)pa;

  acquire(&kmem.lock);
  r->next = kmem.freelist;
  kmem.freelist = r;
  release(&kmem.lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  struct run *r;

  acquire(&kmem.lock);
  r = kmem.freelist;
  if(r){
    int index = kgetRcIndex(r);
    kmem.rc[index] = 1;
    kmem.freelist = r->next;
  }
  release(&kmem.lock);

  if(r)
    memset((char*)r, 5, PGSIZE); // fill with junk
  return (void*)r;
}
