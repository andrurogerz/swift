#include <sys/wait.h>

static inline
bool wifstopped(int status) {
  return WIFSTOPPED(status) != 0;
}