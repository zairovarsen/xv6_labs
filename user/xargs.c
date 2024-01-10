#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/param.h" 

int
getcmd(char *buf, int nbuf)
{
  memset(buf,0,nbuf);
  gets(buf, nbuf);
  if(buf[0] == 0)
    return -1;
  return 0;
}

void runcmd(char *cmd, char *args[]) 
{
     if (fork() == 0){
       exec(cmd,args);
     }
     wait(0);
}

int 
main(int argc, char *argv[])
{
   static char buf[MAXARG][100];
   char *xargs[MAXARG];
   int n = 0;

   for (int i = 1; i < argc; i++){
     xargs[i-1] = argv[i];
   }

   while(getcmd(buf[n], 100) >= 0){
      buf[n][strlen(buf[n])-1] = 0;
      n++;
   }

   if (n >= MAXARG) {
     fprintf(2, "xargs: too many arguments\n");  
     exit(1);
   }

   for (int i = 0; i < n; i++) {
     xargs[argc-1] = buf[i];
     runcmd(xargs[0], xargs);
   }
   
   exit(0);
}

