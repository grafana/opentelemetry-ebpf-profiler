#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


/**
 * Error codes exposed to the C API.
 *
 * The errors that we are exposing are currently rather coarsely mapped.
 * In the future, it probably makes sense to expose sub-errors more granularly.
 */
typedef enum SymblibStatus {
  Ok = 0,
  IoMisc = 1,
  IoFileNotFound = 2,
  Objfile = 3,
  Dwarf = 4,
  Symbconv = 5,
  Retpad = 6,
  BadUtf8 = 7,
  AlreadyClosed = 8,
  InvalidSymdbTablePath = 9,
  U32Overflow = 10,
} SymblibStatus;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

enum SymblibStatus symblib_exe_fd_to_table(int executable_fd, int dwarf_sup_fd, int output_fd);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
