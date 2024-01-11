#include "kernel/types.h" 
#include "kernel/stat.h"
#include "user/user.h"

int main(int argc, char * argv[]) {
  int fd[2];
  char buf[10];

  if (pipe(fd) == -1) {
    fprintf(2, "Pipe call fail\n");
    exit(1);
  }


  if (fork() == 0) {
    if (read(fd[0], buf, 1) == 1) {
      fprintf(1,"%d: received ping\n", getpid());  
      buf[0] = 'a';
      write(fd[1], buf, 1);
      exit(0);
    }
    exit(0);
  } else {
    write(fd[1], buf, 1);
    if (read(fd[0], buf, 1) == 1) {
      fprintf(1,"%d: received pong\n", getpid());  
    }
    exit(0);
  }
  
}
