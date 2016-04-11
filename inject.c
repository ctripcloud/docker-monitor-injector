#define _GNU_SOURCE
#include <dlfcn.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <stdbool.h>
#include <asm-generic/fcntl.h>
#include <errno.h>

#define INJECT_TARGETS "CONTAINER_PROC_INJECT_TARGETS"
#define TMPFILE_MAGIC "E234Dde28Axc"
#define PROCLEN 100

// include fctnl.h will import declaration of open
// conflict with our injection
extern int fcntl(int fd, int cmd, ...);

#ifdef INJECT_DEBUG
#define DEBUG_LOG(...) do {						\
			   fprintf(stderr, "%s@%d: ", __FILE__, __LINE__); \
			   fprintf(stderr, __VA_ARGS__);		\
			   fprintf(stderr, "\n");			\
			   } while(0)
#else
#define DEBUG_LOG(...)
#endif

static void _init() __attribute__((constructor));

typedef ssize_t (*glibc_open)(const char*, int, mode_t);
typedef FILE* (*glibc_fopen)(const char*, const char*);
typedef off_t (*glibc_lseek)(int, off_t, int);
typedef int (*glibc_sysinfo)(struct sysinfo *);
typedef long (*glibc_sysconf)(int name);
typedef int (*proc_reader)(FILE *f);

static glibc_open _orig_open;
static glibc_fopen _orig_fopen;
static glibc_lseek _orig_lseek;
static glibc_sysinfo _orig_sysinfo;
static glibc_sysconf _orig_sysconf;


static char *basedir = "/sys/fs/cgroup";

static bool inject_open;

struct inject_reader {
  char *target_path;
  char *tmp_file_template;
  proc_reader reader_func;
};

static int orig_open(const char *pathname, int flags, mode_t mode) {
  if (!_orig_open) {
      _orig_open = (glibc_open)dlsym(RTLD_NEXT, "open");
  }

  return _orig_open(pathname, flags, mode);
}

static FILE* orig_fopen(const char *pathname, const char *mode) {
  if (!_orig_fopen) {
      _orig_fopen = (glibc_fopen)dlsym(RTLD_NEXT, "fopen");
  }

  return _orig_fopen(pathname, mode);
}

static off_t orig_lseek(int fd, off_t offset, int whence) {
  if (!_orig_lseek) {
      _orig_lseek = (glibc_lseek)dlsym(RTLD_NEXT, "lseek");
  }

  return _orig_lseek(fd, offset, whence);
}

static int orig_sysinfo(struct sysinfo *info) {
  if (!_orig_sysinfo) {
      _orig_sysinfo = (glibc_sysinfo)dlsym(RTLD_NEXT, "sysinfo");
  }

  return _orig_sysinfo(info);
}

static long orig_sysconf(int name) {
  if (!_orig_sysconf) {
      _orig_sysconf = (glibc_sysconf)dlsym(RTLD_NEXT, "sysconf");
  }

  return _orig_sysconf(name);
}

static bool is_inject_target() {
  char exe[1024];
  char *base;
  ssize_t ret;

  ret = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  if (ret == -1) {
    return false;
  }
  exe[ret] = 0;
  base = basename(exe);
  
  char *targets = getenv(INJECT_TARGETS);
  if (targets) {
    char *target = strtok(targets, ":");

    while (target) {
      if (0 == strcmp(base, target)) {
	return true;
      }

      target = strtok(NULL, ":");
    }
  }

  return false;
}

static bool startswith(const char *line, const char *pref)
{
  if (strncmp(line, pref, strlen(pref)) == 0)
    return true;
  return false;
}

static inline void drop_trailing_newlines(char *s)
{
  int l;

  for (l=strlen(s); l>0 && s[l-1] == '\n'; l--)
    s[l-1] = '\0';
}

#define BATCH_SIZE 50
static void dorealloc(char **mem, size_t oldlen, size_t newlen)
{
  int newbatches = (newlen / BATCH_SIZE) + 1;
  int oldbatches = (oldlen / BATCH_SIZE) + 1;

  if (!*mem || newbatches > oldbatches) {
    char *tmp;
    do {
      tmp = realloc(*mem, newbatches * BATCH_SIZE);
    } while (!tmp);
    *mem = tmp;
  }
}

static void append_line(char **contents, size_t *len, char *line, ssize_t linelen) {

  size_t newlen = *len + linelen;
  dorealloc(contents, *len, newlen + 1);
  memcpy(*contents + *len, line, linelen+1);
  *len = newlen;
}

static FILE *safe_fopen_r(const char *filename) {
  int fd = orig_open(filename, O_RDONLY, 0);
  if (fd >= 0) {
    return fdopen(fd, "r");
  }
  return NULL;
}

static char *read_file(const char *from) {

  char *line = NULL;
  char *contents = NULL;
  FILE *f = safe_fopen_r(from);
  size_t len = 0, fulllen = 0;
  ssize_t linelen;

  if (!f) {
    DEBUG_LOG("failed to open %s\n", from);
    return NULL;
  }

  while ((linelen = getline(&line, &len, f)) != -1) {
    append_line(&contents, &fulllen, line, linelen);
  }
  fclose(f);

  if (contents)
    drop_trailing_newlines(contents);
  free(line);
  return contents;
}

bool cgfs_get_value(const char *controller, const char *cgroup, const char *file, char **value) {

  size_t len;
  char *fnam;

  if (!controller)
    return false;

  len = strlen(basedir) + strlen(controller) + strlen(cgroup) + strlen(file) + 4;
  fnam = alloca(len);
  snprintf(fnam, len, "%s/%s/%s/%s", basedir, controller, cgroup, file);

  *value = read_file(fnam);
  if (!*value) {
    DEBUG_LOG("reading file %s failed!\n", fnam);
  }
  return *value != NULL;
}

static void stripnewline(char *x)
{
  size_t l = strlen(x);
  if (l && x[l-1] == '\n')
    x[l-1] = '\0';
}

static char* get_cgroup(char *control) {
  FILE *f;
  char *answer = NULL;
  char *line = NULL;
  size_t len = 0;

  if (!(f = safe_fopen_r("/proc/self/cgroup")))
    return NULL;

  while (getline(&line, &len, f) != -1) {
    char *c1, *c2;
    if (!line[0])
      continue;
    c1 = strchr(line, ':');
    if (!c1)
      goto out;
    c1++;
    c2 = strchr(c1, ':');
    if (!c2)
      goto out;
    *c2 = '\0';
    if (strcmp(c1, control) != 0)
      continue;
    c2++;
    stripnewline(c2);
    do {
      answer = strdup(c2);
    } while (!answer);
    break;
  }

 out:
  fclose(f);
  free(line);
  return answer;
}

static unsigned long get_reaper_busy()
{
  char *cgroup = NULL, *usage_str = NULL;
  unsigned long usage = 0;
  char cgroup_names[] = "cpuacct;cpuacct,cpu;cpu,cpuacct";
  char *cgroup_name = strtok(cgroup_names, ";");

  while (cgroup_name && !cgroup) {
    cgroup = get_cgroup(cgroup_name);
    cgroup_name = strtok(NULL, ";");
  }

  if (!cgroup)
    goto out;
  if (!cgfs_get_value("cpuacct", cgroup, "cpuacct.usage", &usage_str))
    goto out;
  usage = strtoul(usage_str, NULL, 10);
  usage /= 1000000000;

 out:
  free(cgroup);
  free(usage_str);
  return usage;
}

static long int getreaperage()
{
  struct stat sb;

  if (lstat("/proc/1", &sb) < 0)
    return 0;

  return time(NULL) - sb.st_ctime;
}

/*
 * We read /proc/uptime and reuse its second field.
 * For the first field, we use the mtime for the reaper for
 * the calling pid as returned by getreaperage
 */
static int read_proc_uptime(FILE *f) {
  long int reaperage = getreaperage();
  unsigned long int busytime = get_reaper_busy(), idletime;
  size_t total_len = 0;

  idletime = reaperage - busytime;
  if (idletime > reaperage)
    idletime = reaperage;

  total_len = fprintf(f, "%ld.0 %lu.0\n", reaperage, idletime);
  return total_len;
}

static void get_mem_cached(char *memstat, unsigned long *v)
{
  char *eol;
  
  *v = 0;
  while (*memstat) {
    if (startswith(memstat, "total_cache")) {
      sscanf(memstat + 11, "%lu", v);
      *v /= 1024;
      return;
    }
    eol = strchr(memstat, '\n');
    if (!eol)
      return;
    memstat = eol+1;
  }
}

static unsigned long get_memlimit(const char *cgroup)
{
  char *memlimit_str = NULL;
  unsigned long memlimit = -1;

  if (cgfs_get_value("memory", cgroup, "memory.limit_in_bytes", &memlimit_str))
    memlimit = strtoul(memlimit_str, NULL, 10);

  free(memlimit_str);

  return memlimit;
}

static unsigned long get_min_memlimit(const char *cgroup)
{
  char *copy = strdupa(cgroup);
  unsigned long memlimit = 0, retlimit;

  retlimit = get_memlimit(copy);

  while (strcmp(copy, "/") != 0) {
    copy = dirname(copy);
    memlimit = get_memlimit(copy);
    if (memlimit != -1 && memlimit < retlimit)
      retlimit = memlimit;
  };

  return retlimit;
}

typedef struct {
  unsigned long memtotal;
  unsigned long memfree;
  unsigned long swaptotal;
  unsigned long swapfree;
  unsigned long buffers;
  unsigned long cached;
  unsigned long swapcached;
  unsigned long slab;
} meminfo;


static bool get_container_meminfo(meminfo *info, unsigned int unit) {
  bool ret = false;
  char *cg;

  char *memusage_str = NULL, *memstat_str = NULL,
    *memswlimit_str = NULL, *memswusage_str = NULL,
    *memswlimit_default_str = NULL, *memswusage_default_str = NULL;
  unsigned long memlimit = 0, memusage = 0, memswlimit = 0, memswusage = 0,
    hosttotal = 0;
  char *line = NULL;
  size_t linelen = 0;
  FILE *meminfo;

  memset(info, sizeof(meminfo), 0);

  cg = get_cgroup("memory");
  if (!cg)
    return -1;

  DEBUG_LOG("Calc meminfo from cg %s", cg);

  memlimit = get_min_memlimit(cg);
  if (!cgfs_get_value("memory", cg, "memory.usage_in_bytes", &memusage_str))
    goto err;
  if (!cgfs_get_value("memory", cg, "memory.stat", &memstat_str))
    goto err;

  // Following values are allowed to fail, because swapaccount might be turned
  // off for current kernel
  if(cgfs_get_value("memory", cg, "memory.memsw.limit_in_bytes", &memswlimit_str) &&
     cgfs_get_value("memory", cg, "memory.memsw.usage_in_bytes", &memswusage_str))
    {
      /* If swapaccounting is turned on, then default value is assumed to be that of cgroup / */
      if (!cgfs_get_value("memory", "/", "memory.memsw.limit_in_bytes", &memswlimit_default_str))
	goto err;
      if (!cgfs_get_value("memory", "/", "memory.memsw.usage_in_bytes", &memswusage_default_str))
	goto err;

      memswlimit = strtoul(memswlimit_str, NULL, 10);
      memswusage = strtoul(memswusage_str, NULL, 10);

      if (!strcmp(memswlimit_str, memswlimit_default_str))
	memswlimit = 0;
      if (!strcmp(memswusage_str, memswusage_default_str))
	memswusage = 0;

      memswlimit = memswlimit / unit;
      memswusage = memswusage / unit;
    }

  memusage = strtoul(memusage_str, NULL, 10);
  memlimit /= unit;
  memusage /= unit;

  get_mem_cached(memstat_str, &(info->cached));

  meminfo = safe_fopen_r("/proc/meminfo");
  if (!meminfo) {
    goto err;
  }

  while (getline(&line, &linelen, meminfo) != -1) {
    if (startswith(line, "MemTotal:")) {
      sscanf(line+14, "%lu", &hosttotal);
      hosttotal = hosttotal * 1024 / unit;
      if (hosttotal < memlimit)
        memlimit = hosttotal;
      info->memtotal = memlimit;
      DEBUG_LOG("calced MemTotal:%ld", memlimit);
    } else if (startswith(line, "MemFree:")) {
      info->memfree = memlimit - memusage;
    } else if (startswith(line, "SwapTotal:")) {
      if ( memswlimit > 0) {
        info->swaptotal = memswlimit - memlimit;
      } else {
        info->swaptotal = 0;
      }
      DEBUG_LOG("calced SwapTotal:      %8lu\n", info->swaptotal);
    } else if (startswith(line, "SwapFree:")) {
      if (memswlimit > 0 && memswusage > 0) {
	    info->swapfree = (memswlimit - memlimit) - (memswusage - memusage);
      } else {
        info->swapfree = 0;
      }
      DEBUG_LOG("calced SwapFree: %lu \n", info->swapfree);
    }
  }

  ret = true;

err:
  if (meminfo)
    fclose(meminfo);
  free(line);
  free(cg);
  free(memusage_str);
  free(memswlimit_str);
  free(memswusage_str);
  free(memstat_str);
  free(memswlimit_default_str);
  free(memswusage_default_str);
  return ret;
}

static int read_proc_meminfo(FILE *f) {
  meminfo info;
  bool read_succeed;
  read_succeed = get_container_meminfo(&info, 1024);

  char *line = NULL;
  size_t linelen = 0, rv = -1;
  FILE *meminfo;

  meminfo = safe_fopen_r("/proc/meminfo");
  if (!meminfo) {
    goto err;
  }

  while(getline(&line, &linelen, meminfo) != -1) {
    size_t l;
    char *printme, lbuf[100];

    memset(lbuf, 0, 100);
    if (startswith(line, "MemTotal:") && read_succeed) {
      snprintf(lbuf, 100, "MemTotal:       %8lu kB\n", info.memtotal);
      printme = lbuf;
    } else if (startswith(line, "MemFree:") && read_succeed) {
      snprintf(lbuf, 100, "MemFree:        %8lu kB\n", info.memfree);
      printme = lbuf;
    } else if (startswith(line, "MemAvailable:") && read_succeed) {
      snprintf(lbuf, 100, "MemAvailable:   %8lu kB\n", info.memfree);
      printme = lbuf;
    } else if (startswith(line, "SwapTotal:") && read_succeed) {
      snprintf(lbuf, 100, "SwapTotal:      %8lu kB\n", info.swaptotal);
      printme = lbuf;
    } else if (startswith(line, "SwapFree:") && read_succeed) {
      snprintf(lbuf, 100, "SwapFree:       %8lu kB\n", info.swapfree);
      printme = lbuf;
    } else if (startswith(line, "Buffers:")) {
      snprintf(lbuf, 100, "Buffers:        %8lu kB\n", 0UL);
      printme = lbuf;
    } else if (startswith(line, "Cached:") && read_succeed) {
      snprintf(lbuf, 100, "Cached:         %8lu kB\n", info.cached);
      printme = lbuf;
    } else if (startswith(line, "SwapCached:")) {
      snprintf(lbuf, 100, "SwapCached:     %8lu kB\n", 0UL);
      printme = lbuf;
    } else if (startswith(line, "Slab:")) {
      // hack, cgroup slabinfo not support in kernel
      snprintf(lbuf, 100, "Slab:           %8lu kB\n", 0UL);
      printme = lbuf;
    } else
      printme = line;

    l = fprintf(f, "%s", printme);
    if (l < 0) {
      goto err;

    }
    rv = rv + l;
  }

 err:
  if (meminfo)
    fclose(meminfo);
  free(line);
  return rv;
}

/*
 * Helper functions for cpuset_in-set
 */
static char *cpuset_nexttok(const char *c)
{
  char *r = strchr(c+1, ',');
  if (r)
    return r+1;
  return NULL;
}

static int cpuset_getrange(const char *c, int *a, int *b)
{
  int ret;

  ret = sscanf(c, "%d-%d", a, b);
  return ret;
}

/*
 * cpusets are in format "1,2-3,4"
 * iow, comma-delimited ranges
 */
static bool cpu_in_cpuset(int cpu, const char *cpuset)
{
  const char *c;

  for (c = cpuset; c; c = cpuset_nexttok(c)) {
    int a, b, ret;

    ret = cpuset_getrange(c, &a, &b);
    if (ret == 1 && cpu == a) // "1" or "1,6"
      return true;
    else if (ret == 2 && cpu >= a && cpu <= b) // range match
      return true;
  }

  return false;
}


static unsigned long get_btime() {
  struct stat sb;

  if (lstat("/proc/1", &sb) < 0)
    return 0;

  return sb.st_ctime;
}

static unsigned short count_procs() {
  char *cg;
  unsigned short ret = 0;
  char *procs_str;
  cg = get_cgroup("memory");
  if (!cgfs_get_value("memory", cg, "tasks", &procs_str)) {
    goto err;
  }

  char *eol = procs_str;
  while((eol = strchr(eol, '\n')) != NULL) {
    ret++;
    eol++;
  }
err:
  free(procs_str);
  return ret;
}


static unsigned int get_cpushares() {
  char *cg = NULL;
  char *shares_str = NULL;
  char cgroup_names[] = "cpu;cpuacct,cpu;cpu,cpuacct";
  char *cgroup_name = strtok(cgroup_names, ";");
  unsigned int ret = 0;

  while (cgroup_name && !cg) {
    cg = get_cgroup(cgroup_name);
    cgroup_name = strtok(NULL, ";");
  }

  if (!cg) {
    DEBUG_LOG("failed to get cgroup cpu");
    goto out;
  }
  if (!cgfs_get_value("cpu", cg, "cpu.shares", &shares_str)) {
    DEBUG_LOG("failed to get cpu.shares!");
    goto out;
  }
  DEBUG_LOG("get cpu share %s", shares_str);
  sscanf(shares_str, "%d", &ret);

out:
  free(cg);
  free(shares_str);
  return ret;
}

static char* get_cpuset() {
  char *cg = NULL;
  char *ret = NULL;

  cg = get_cgroup("cpuset");
  if (!cg) {
    DEBUG_LOG("failed to get cgroup cpuset");
    goto err;
  }

  if(!cgfs_get_value("cpuset", cg, "cpuset.cpus", &ret)) {
    DEBUG_LOG("failed to read cpuset.cpus");
    goto err;
  }
err:
  free(cg);
  return ret;
}

static unsigned int count_cpus_in_cpuset(const char *cpuset) {
  unsigned int ret = 0;
  for (const char *c = cpuset; c; c = cpuset_nexttok(c)) {
    int a, b;

    if (cpuset_getrange(c, &a, &b) == 1) {
      ret++;
    } else {
      ret += (b - a) + 1;
    }
  }
  return ret;
}


static bool allocated_by_cpushares() {
  char *cpuset = get_cpuset();
  bool ret = true;
  int total_cpu_num = orig_sysconf(_SC_NPROCESSORS_ONLN);
  int cpuset_num = 0;
  if (!cpuset) {
    DEBUG_LOG("failed to get cpuset.");
    goto err;
  }
  cpuset_num = count_cpus_in_cpuset(cpuset);
  ret = cpuset_num == total_cpu_num;
err:
  free(cpuset);
  return ret;
}

static int read_proc_stat_by_cpusets(FILE *statf) {
  char *cpuset = NULL;
  char *line = NULL;
  size_t linelen = 0, total_len = 0, rv = 0;
  int curcpu = -1; /* cpu numbering starts at 0 */
  unsigned long user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0, guest = 0;
  unsigned long user_sum = 0, nice_sum = 0, system_sum = 0, idle_sum = 0, iowait_sum = 0,
          irq_sum = 0, softirq_sum = 0, steal_sum = 0, guest_sum = 0;

#define CPUALL_MAX_SIZE 256
  char cpuall[CPUALL_MAX_SIZE];
  size_t buf_size = CPUALL_MAX_SIZE * 64;
  char *buf = malloc(buf_size);

  if (!buf) {
    DEBUG_LOG("failed to allocate memory for stat buffer");
    return -1;
  }
  memset(buf, 0, buf_size);
  
  char *cache = buf;
  size_t cache_size = buf_size;

  if(!(cpuset = get_cpuset())) {
    DEBUG_LOG("failed to read cpuset.cpus");
    goto err;
  }

  FILE *f = safe_fopen_r("/proc/stat");
  if (!f) {
    DEBUG_LOG("unable to open /proc/stat");
    goto err;
  }

  //skip first line
  if (getline(&line, &linelen, f) < 0) {
    DEBUG_LOG("read_proc_stat skip first line failed\n");
    goto err;
  }

  while (getline(&line, &linelen, f) != -1) {
    size_t l;
    int cpu;
    char cpu_char[10]; /* That's a lot of cores */
    char *c;

    if (sscanf(line, "cpu%9[^ ]", cpu_char) != 1) {
      if (startswith(line, "btime")) {
        l = snprintf(cache, cache_size, "btime %ld\n", get_btime());
      } else {
        l = snprintf(cache, cache_size, "%s", line);
      }
      if (l < 0) {
        perror("Error writing to cache");
        goto err;
      }
      if (l >= cache_size) {
        fprintf(stderr, "Internal error: truncated write to cache\n");
        goto err;
      }
      cache += l;
      cache_size -= l;
      total_len += l;
      continue;
    }

    if (sscanf(cpu_char, "%d", &cpu) != 1)
      continue;
    if (!cpu_in_cpuset(cpu, cpuset))
      continue;
    curcpu ++;

    c = strchr(line, ' ');
    if (!c)
      continue;
    l = snprintf(cache, cache_size, "cpu%d%s", curcpu, c);
    if (l < 0) {
      perror("Error writing to cache");
      goto err;

    }
    if (l >= cache_size) {
      DEBUG_LOG("Internal error: truncated write to cache\n");
      goto err;
    }

    cache += l;
    cache_size -= l;
    total_len += l;

    if (sscanf(line, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu", &user, &nice, &system, &idle, &iowait, &irq,
      &softirq, &steal, &guest) != 9)
      continue;
    user_sum += user;
    nice_sum += nice;
    system_sum += system;
    idle_sum += idle;
    iowait_sum += iowait;
    irq_sum += irq;
    softirq_sum += softirq;
    steal_sum += steal;
    guest_sum += guest;
  }

  int cpuall_len = snprintf(cpuall, CPUALL_MAX_SIZE, "%s %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
    "cpu ", user_sum, nice_sum, system_sum, idle_sum, iowait_sum, irq_sum, softirq_sum, steal_sum, guest_sum);
  if (cpuall_len <= 0 && cpuall_len >= CPUALL_MAX_SIZE) {
    /* shouldn't happen */
    DEBUG_LOG("proc_stat_read copy cpuall failed, cpuall_len=%d\n", cpuall_len);
    cpuall_len = 0;
  }

  fprintf(statf, "%s%s", cpuall, buf);

  total_len += cpuall_len;
  rv = total_len;

err:
  if (f)
    fclose(f);
  free(line);
  free(cpuset);
  free(buf);
  return rv;
}


static int read_proc_stat_by_shares(FILE *statf) {
  int cpu_num = get_cpushares() / 1024;
  int total_cpu_num = orig_sysconf(_SC_NPROCESSORS_ONLN);
  char *cg = NULL;
  char *cpuacct_stat_str = NULL;
  char *line = NULL;
  size_t linelen = 0, rv = 0;
  unsigned long user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0, guest = 0;
  unsigned long user_sum = 0, nice_sum = 0, system_sum = 0, idle_sum = 0, iowait_sum = 0,
          irq_sum = 0, softirq_sum = 0, steal_sum = 0, guest_sum = 0;

  char cgroup_names[] = "cpuacct;cpuacct,cpu;cpu,cpuacct";
  char *cgroup_name = strtok(cgroup_names, ";");

  while (cgroup_name && !cg) {
    cg = get_cgroup(cgroup_name);
    cgroup_name = strtok(NULL, ";");
  }

  if (!cg) {
    DEBUG_LOG("failed to get cgroup cpuacct");
    return -1;
  }

  if (!cgfs_get_value("cpuacct", cg, "cpuacct.stat", &cpuacct_stat_str)) {
    DEBUG_LOG("failed to read cpuacct.stat");
    goto err;
  }

  sscanf(cpuacct_stat_str, "user %lu\nsystem %lu", &user_sum, &system_sum);

  FILE *f = safe_fopen_r("/proc/stat");
  if (!f) {
    DEBUG_LOG("unable to open /proc/stat");
    goto err;
  }

  if (getline(&line, &linelen, f) < 0) {
    DEBUG_LOG("failed to read first line of /proc/stat");
    goto err;
  }

  if (sscanf(line, "cpu %*u %lu %*u %lu %lu %lu %lu %lu %lu", &nice_sum,
      &idle_sum, &iowait_sum, &irq_sum, &softirq_sum, &steal_sum, &guest_sum) != 7) {
    DEBUG_LOG("failed to read total cpu usage.");
    goto err;
  }
#define FACTOR_STAT(name) name=(name*cpu_num)/total_cpu_num
  FACTOR_STAT(nice_sum);
  FACTOR_STAT(idle_sum);
  FACTOR_STAT(iowait_sum);
  FACTOR_STAT(irq_sum);
  FACTOR_STAT(softirq_sum);
  FACTOR_STAT(steal_sum);
  FACTOR_STAT(guest_sum);
  fprintf(statf, "cpu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n", user_sum, nice_sum,
      system_sum, idle_sum, iowait_sum, irq_sum, softirq_sum, steal_sum, guest_sum);

  user = user_sum/cpu_num; nice = nice_sum/cpu_num; system = system_sum/cpu_num;
  idle = idle_sum/cpu_num; iowait = iowait_sum/cpu_num; irq = irq_sum/cpu_num;
  softirq = softirq_sum/cpu_num; steal = steal_sum/cpu_num; guest = guest_sum/cpu_num;
  for (int i=0; i < cpu_num; i++) {
  fprintf(statf, "cpu%d %lu %lu %lu %lu %lu %lu %lu %lu %lu\n", i, user, nice,
      system, idle, iowait, irq, softirq, steal, guest);
  }

  while (getline(&line, &linelen, f) != -1) {
    if (startswith(line, "cpu")) {
      continue;
    }
    if (startswith(line, "btime")) {
      fprintf(statf, "btime %ld\n", get_btime());
    } else {
      fprintf(statf, "%s", line);
    }
  }

err:
  if (f)
    fclose(f);
  free(line);
  free(cg);
  free(cpuacct_stat_str);
  return rv;
}


static int read_proc_stat(FILE *statf) {
  if (allocated_by_cpushares()) {
    DEBUG_LOG("get cpu by shares");
    return read_proc_stat_by_shares(statf);
  } else {
    DEBUG_LOG("get cpu by cpusets");
    return read_proc_stat_by_cpusets(statf);
  }
}

static void get_blkio_io_value(char *str, unsigned major, unsigned minor, char *iotype, unsigned long *v)
{
  char *eol;
  char key[32];

  memset(key, 0, 32);
  snprintf(key, 32, "%u:%u %s", major, minor, iotype);

  size_t len = strlen(key);
  *v = 0;

  while (*str) {
    if (startswith(str, key)) {
      sscanf(str + len, "%lu", v);
      return;
    }
    eol = strchr(str, '\n');
    if (!eol)
      return;
    str = eol+1;
  }
}

static int read_proc_diskstats(FILE *f) {
  char dev_name[72];
  char *cg;
  char *io_serviced_str = NULL, *io_merged_str = NULL, *io_service_bytes_str = NULL,
      *io_wait_time_str = NULL, *io_service_time_str = NULL;
  unsigned long read = 0, write = 0;
  unsigned long read_merged = 0, write_merged = 0;
  unsigned long read_sectors = 0, write_sectors = 0;
  unsigned long read_ticks = 0, write_ticks = 0;
  unsigned long ios_pgr = 0, tot_ticks = 0, rq_ticks = 0;
  unsigned long rd_svctm = 0, wr_svctm = 0, rd_wait = 0, wr_wait = 0;
  char *line = NULL;
  size_t linelen = 0, total_len = 0, rv = 0;
  unsigned int major = 0, minor = 0;
  int i = 0;
  FILE *sourcef;

  cg = get_cgroup("blkio");
  if (!cg) {
    DEBUG_LOG("failed to get cgroup blkio");
    return -1;
  }

  if (!cgfs_get_value("blkio", cg, "blkio.io_serviced", &io_serviced_str))
    goto err;
  if (!cgfs_get_value("blkio", cg, "blkio.io_merged", &io_merged_str))
    goto err;
  if (!cgfs_get_value("blkio", cg, "blkio.io_service_bytes", &io_service_bytes_str))
    goto err;
  if (!cgfs_get_value("blkio", cg, "blkio.io_wait_time", &io_wait_time_str))
    goto err;
  if (!cgfs_get_value("blkio", cg, "blkio.io_service_time", &io_service_time_str))
    goto err;


  sourcef = orig_fopen("/proc/diskstats", "r");
  if (!f)
    goto err;

  while (getline(&line, &linelen, sourcef) != -1) {
    size_t l;
    char *printme, lbuf[256];

    i = sscanf(line, "%u %u %71s", &major, &minor, dev_name);
    if(i == 3){
      get_blkio_io_value(io_serviced_str, major, minor, "Read", &read);
      get_blkio_io_value(io_serviced_str, major, minor, "Write", &write);
      get_blkio_io_value(io_merged_str, major, minor, "Read", &read_merged);
      get_blkio_io_value(io_merged_str, major, minor, "Write", &write_merged);
      get_blkio_io_value(io_service_bytes_str, major, minor, "Read", &read_sectors);
      read_sectors = read_sectors/512;
      get_blkio_io_value(io_service_bytes_str, major, minor, "Write", &write_sectors);
      write_sectors = write_sectors/512;

      get_blkio_io_value(io_service_time_str, major, minor, "Read", &rd_svctm);
      rd_svctm = rd_svctm/1000000;
      get_blkio_io_value(io_wait_time_str, major, minor, "Read", &rd_wait);
      rd_wait = rd_wait/1000000;
      read_ticks = rd_svctm + rd_wait;

      get_blkio_io_value(io_service_time_str, major, minor, "Write", &wr_svctm);
      wr_svctm =  wr_svctm/1000000;
      get_blkio_io_value(io_wait_time_str, major, minor, "Write", &wr_wait);
      wr_wait =  wr_wait/1000000;
      write_ticks = wr_svctm + wr_wait;

      get_blkio_io_value(io_service_time_str, major, minor, "Total", &tot_ticks);
      tot_ticks =  tot_ticks/1000000;
    }else{
      continue;
    }

    memset(lbuf, 0, 256);
    if (read || write || read_merged || write_merged || read_sectors || write_sectors || read_ticks || write_ticks) {
      snprintf(lbuf, 256, "%u       %u %s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
        major, minor, dev_name, read, read_merged, read_sectors, read_ticks,
        write, write_merged, write_sectors, write_ticks, ios_pgr, tot_ticks, rq_ticks);
      printme = lbuf;
    } else
      continue;

    l = fprintf(f, "%s", printme);
    if (l < 0) {
      perror("Error writing to fuse buf");
      rv = 0;
      goto err;
    }
    total_len += l;
  }

  rv = total_len;

err:
  free(cg);
  if (sourcef)
    fclose(sourcef);
  free(line);
  free(io_serviced_str);
  free(io_merged_str);
  free(io_service_bytes_str);
  free(io_wait_time_str);
  free(io_service_time_str);
  return rv;
}

static bool cpuline_in_cpuset(const char *line, const char *cpuset)
{
  int cpu;

  if (sscanf(line, "processor       : %d", &cpu) != 1)
    return false;
  return cpu_in_cpuset(cpu, cpuset);
}


static bool is_processor_line(const char *line)
{
  int cpu;

  if (sscanf(line, "processor       : %d", &cpu) == 1)
    return true;
  return false;
}

static int read_proc_cpuinfo(FILE *f) {
  char *cg;
  char *cpuset = NULL;
  char *line = NULL;
  size_t linelen = 0, total_len = 0, rv = 0;
  bool am_printing = false;
  bool by_cpushares = allocated_by_cpushares();
  long cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
  int curcpu = 0;
  FILE *cpuinfo = NULL;

  cg = get_cgroup("cpuset");
  if (!cg) {
    DEBUG_LOG("failed to get cgroup cpuset");
  }

  if (!cgfs_get_value("cpuset", cg, "cpuset.cpus", &cpuset))
    goto err;
  if (!cpuset)
    goto err;

  cpuinfo = orig_fopen("/proc/cpuinfo", "r");
  if (!cpuinfo)
    goto err;
  while (getline(&line, &linelen, cpuinfo) != -1) {
    size_t l;
    if (is_processor_line(line)) {
      if (by_cpushares) {
        am_printing = curcpu < cpu_num;
      } else {
        am_printing = cpuline_in_cpuset(line, cpuset);
      }
      if (am_printing) {
        l = fprintf(f, "processor  : %d\n", curcpu++);
        if (l < 0) {
          perror("Error writing to cache");
          rv = 0;
          goto err;
        }
        total_len += l;
      }
      continue;
    }
    if (am_printing) {
      l = fprintf(f, "%s", line);
      if (l < 0) {
        perror("Error writing to cache");
        rv = 0;
        goto err;
      }
      total_len += l;
    }
  }

  rv = total_len;

err:
  if (cpuinfo)
    fclose(cpuinfo);
  free(line);
  free(cpuset);
  free(cg);
  return rv;
}

static int read_cpu_online(FILE *f) {
  char *cpuset = NULL;
  int ret = 0;
  int cpu_num;
  if (!allocated_by_cpushares()) {
    cpuset = get_cpuset();
    if (cpuset) {
      fprintf(f, "%s", cpuset);
      goto out;
    }
  }
  cpu_num = get_cpushares() / 1024;
  fprintf(f, "0-%d\n", cpu_num - 1);

out:
  free(cpuset);
  return ret;
}

static void get_fd_name(int fd, char *name, ssize_t size) {
  char fd_name[128];
  int ret = snprintf(fd_name, sizeof(fd_name), "/proc/self/fd/%d", fd);

  bzero(name, size);
  if (ret < sizeof(fd_name)) {
    ret = readlink(fd_name, name, size);
    if (-1 == ret) {
      bzero(name, size);
    }
  }
}

static int open_container_data(proc_reader func, char* file_temp, int flags, mode_t mode) {
  char tmpfile[128];
  int ret = -1;
  int fd;

  snprintf(tmpfile, sizeof(tmpfile), "%sXXXXXX", file_temp);
  fd = mkostemp(tmpfile, O_RDWR);

  FILE *f = fdopen(fd, "w");

  if (f) {
    get_fd_name(fd, tmpfile, sizeof(tmpfile));
    ret = orig_open(tmpfile, flags, mode);
    DEBUG_LOG("Open injected file %s as fd: %d", tmpfile, ret);
    unlink(tmpfile);

    if (ret > -1 && func(f) < 0) {
      close(ret);
      ret = -1;
    }
    fclose(f);
  }

  return ret;
}

struct inject_reader readers[] = {
  {"/proc/uptime", "/tmp/"TMPFILE_MAGIC"proc_uptime", read_proc_uptime},
  {"/proc/meminfo", "/tmp/"TMPFILE_MAGIC"proc_meminfo", read_proc_meminfo},
  {"/proc/stat",  "/tmp/"TMPFILE_MAGIC"proc_stat", read_proc_stat},
  {"/proc/diskstats", "/tmp/"TMPFILE_MAGIC"proc_diskstats", read_proc_diskstats},
  {"/proc/cpuinfo", "/tmp/"TMPFILE_MAGIC"proc_cpuinfo", read_proc_cpuinfo},
  {"/sys/devices/system/cpu/online", "/tmp/"TMPFILE_MAGIC"proc_cpuonline", read_cpu_online},
};

#define FOR_EACH_READER(var) struct inject_reader var=readers[0];\
  for(int i=0; i < sizeof(readers)/sizeof(readers[0]); reader=readers[++i])


static int injected_open(const char *pathname, int flags, mode_t mode) {
  int ret = -1;

  DEBUG_LOG("Inject open for file %s", pathname);

  FOR_EACH_READER(reader){
    if (0 == strcmp(reader.target_path, pathname)) {
      ret = open_container_data(reader.reader_func,
                                reader.tmp_file_template,
                                flags, mode);
      break;
    }
  }

  if (ret < 0) {
    DEBUG_LOG("failed to open %s", pathname);
    return orig_open(pathname, flags, mode);
  }
  else
    return ret;
}

static bool is_injected_file(const char *pathname) {
  FOR_EACH_READER(reader){
    if (0 == strcmp(reader.target_path, pathname)) {
      return true;
    }
  }
  return false;
}

static int refresh_container_data(int fd, proc_reader func, char *template) {
  int flags;
  int ret = -1;

  flags = fcntl(fd, F_GETFL);
  if (flags > -1) {
    int tmp_fd;
    tmp_fd = open_container_data(func, template, flags, 0);

    if (tmp_fd > -1) {
      ret = dup2(tmp_fd, fd);
      DEBUG_LOG("Duplicated fd %d based on %d, ret: %d", fd, tmp_fd, ret);
    }
    close(tmp_fd);
  }

  return ret;
}

static off_t injected_lseek(int fd, off_t offset, int whence) {
  char file_name[128];
  get_fd_name(fd, file_name, sizeof(file_name));

  FOR_EACH_READER(reader) {
    if (startswith(file_name, reader.tmp_file_template)) {
      DEBUG_LOG("Inject lseek for fd %d as %s", fd, reader.target_path);
      refresh_container_data(fd, reader.reader_func, reader.tmp_file_template);
      break;
    }
  }
  return orig_lseek(fd, offset, whence);
}


static void _init() {
  DEBUG_LOG("Init stdlib hijack.");
  inject_open = is_inject_target();
}


int open(const char *pathname, int flags, mode_t mode) {
  if (inject_open && is_injected_file(pathname)) {
    return injected_open(pathname, flags, mode);
  }

  return orig_open(pathname, flags, mode);
}

FILE *fopen(const char *pathname, const char *mode) {
  if (inject_open && is_injected_file(pathname)) {
    DEBUG_LOG("inject fdopen %s", pathname);
    int fd = open(pathname, O_RDONLY, 0);
    return fdopen(fd, mode);
  }

  return orig_fopen(pathname, mode);
}

off_t lseek(int fd, off_t offset, int whence) {
  if (inject_open) {
    return injected_lseek(fd, offset, whence);
  }
  return orig_lseek(fd, offset, whence);
}

int sysinfo(struct sysinfo *info) {
  if (!inject_open) {
    return orig_sysinfo(info);
  }
  meminfo minfo;
  int ret;
  if (!get_container_meminfo(&minfo, 1)) {
    DEBUG_LOG("failed to read meminfo from cgroup");
  }

  ret = orig_sysinfo(info);
  if (ret) {
    return ret;
  }
  info->uptime = getreaperage();

  info->mem_unit = 1;
  info->totalram = minfo.memtotal;
  info->totalswap = minfo.swaptotal;
  info->freeswap = minfo.swapfree;
  info->freeram = minfo.memfree;
  info->sharedram = 0;
  info->bufferram = 0;
  info->procs = count_procs();
  ret = 0;
  return ret;
}


long sysconf(int name) {
  DEBUG_LOG("Calling hijacked sysconf");
  if (!inject_open || name != _SC_NPROCESSORS_ONLN) {
    return orig_sysconf(name);
  }

  long total_cpu_num = orig_sysconf(name);
  long ret = total_cpu_num;
  char *cpuset = NULL;

  if (allocated_by_cpushares()) {
    ret = get_cpushares() / 1024;
    goto out;
  }

  if (!(cpuset = get_cpuset())) {
    DEBUG_LOG("failed to get cpuset.");
    goto out;
  }
  ret = count_cpus_in_cpuset(cpuset);

out:
  free(cpuset);
  return ret;
}
