__attribute__((import_module("env"),import_name("sched_fork")))   int  sched_fork(void);
__attribute__((import_module("env"),import_name("sched_yield0")))  void sched_yield0(void);
__attribute__((import_module("env"),import_name("print_num")))     void print_num(int);
_Alignas(16) static unsigned char asyncbuf[0x40000];             // asyncify stack region (256KB)
__attribute__((export_name("asyncbuf_addr"))) unsigned long asyncbuf_addr(void){ return (unsigned long)asyncbuf; }
__attribute__((export_name("run"))) int run(void){
  print_num(1000);
  int pid = sched_fork();
  int base = (pid==0) ? 0 : 500;
  for (int i=0;i<3;i++){ print_num(base+i); sched_yield0(); }
  print_num(base+99);
  return pid;
}
