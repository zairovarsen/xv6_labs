#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"

char*
fmtname(char *path)
{
  static char buf[DIRSIZ+1];
  char *p;

  // Find first character after last slash.
  for(p=path+strlen(path); p >= path && *p != '/'; p--)
    ;
  p++;

  // Return blank-padded name.
  if(strlen(p) >= DIRSIZ)
    return p;
  memmove(buf, p, strlen(p));
  memset(buf+strlen(p), ' ', DIRSIZ-strlen(p));
  return buf;
}

char *
pad(char *name)
{
  static char buf[DIRSIZ+1];

  if (strlen(name) >= DIRSIZ)
    return name;

  memmove(buf,name,strlen(name));
  memset(buf+strlen(name), ' ', DIRSIZ-strlen(name));
  return buf;
}


void 
find(char *path, char *file)
{
   char buf[512], *p;
   int fd;
   struct dirent de;
   struct stat st;
   
   if ((fd = open(path, O_RDONLY)) < 0) {
     fprintf(2, "find: cannot open %s\n", path);
     return;
   }

   if(fstat(fd, &st) < 0){
     fprintf(2, "find: cannot stat %s\n", path);
     close(fd);
     return;
   }

   strcpy(buf,path);
   p = buf + strlen(buf);
   *p++ = '/';

   while(read(fd, &de, sizeof(de)) == sizeof(de)){
     if (de.inum == 0)
       continue;
     
     memmove(p, de.name, DIRSIZ);
     p[DIRSIZ] = 0;
     if (stat(buf, &st) < 0) {
       printf("find: cannot stat %s\n", buf);
       continue;
     }

     char * name = fmtname(buf);
     
     if (st.type == T_DIR) {
       char * dot = pad(".");
       if (strcmp(name, dot) != 0) {
         char * doubledot = pad("..");
         if (strcmp(name, doubledot) != 0) {
           find(buf, file);
         }
       }
     }
     else {
       if (!strcmp(pad(file), name)) {
         printf("%s\n",buf);
       }
     }

   }
   close(fd);
}

int 
main (int argc, char *argv[]) 
{
  find(argv[1], argv[2]);
  exit(0);
}
