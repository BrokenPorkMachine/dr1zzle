#include <ctype.h>
static int in(int c,int a,int z){return c>=a&&c<=z;}
int islower(int c){return in(c,'a','z');} int isupper(int c){return in(c,'A','Z');}
int isalpha(int c){return islower(c)||isupper(c);} int isdigit(int c){return in(c,'0','9');}
int isxdigit(int c){return isdigit(c)||in(c,'a','f')||in(c,'A','F');} int isalnum(int c){return isalpha(c)||isdigit(c);}
int isascii(int c){return c>=0&&c<=127;} int isblank(int c){return c==' '||c=='\t';}
int iscntrl(int c){return c>=0&&(c<32||c==127);} int isprint(int c){return c>=32&&c<127;}
int isgraph(int c){return c>32&&c<127;} int isspace(int c){return c==' '||in(c,'\t','\r');}
int ispunct(int c){return isgraph(c)&&!isalnum(c);} int tolower(int c){return isupper(c)?c+32:c;}
int toupper(int c){return islower(c)?c-32:c;}
