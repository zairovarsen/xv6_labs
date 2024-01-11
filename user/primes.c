#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"


/* read end has all the numbers */
void filter(int read_end) {
  
    int prime;
    read(read_end, &prime, sizeof(int)); // set up for new numbers when creating process 
    printf("prime %d\n", prime);

    int tmp = -1;
    int fd[2];

    pipe(fd);
    while (1) {
      int n = read(read_end, &tmp, sizeof(int));
      if (n  <= 0) {
        break;
      }
      if (tmp % prime != 0) {
        write(fd[1], &tmp, sizeof(int));
      }
    }

    if (tmp == -1) {
      close(fd[0]);
      close(fd[1]);
      close(read_end);
      return;
    }

    if (fork() == 0) {
      close(read_end);
      close(fd[1]);
      filter(fd[0]);
      close(fd[0]);
    } else {
      close(fd[0]);
      close(fd[1]);
    }
    
    wait(0);
    close(read_end);
}

int main(int argc, char * argv[]) {

  int p[2];
  pipe(p);

  for (int i =2; i<=35; i++) {
    int n = i;
    write(p[1], &n, sizeof(int));
  }
  close(p[1]);
  filter(p[0]);
  close(p[0]);
  wait(0);
  exit(0);
}
