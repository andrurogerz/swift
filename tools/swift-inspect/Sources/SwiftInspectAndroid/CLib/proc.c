//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2020 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <stdlib.h>

#include "proc.h"

bool maps_iterate(pid_t pid, maps_entry_callback_t callback, void* context) {
  char filename[256];
  if (snprintf(filename, sizeof(filename), "/proc/%u/maps", pid) < 0)
    return false;

  filename[sizeof(filename)-1] = '\0';

  FILE *file = fopen(filename, "r");
  if (!file) {
    perror("Failed to open /proc/<pid>/maps");
    return false;
  }

  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  while ((read = getline(&line, &len, file)) != -1) {
    maps_entry_t entry = {0};
    const int ret = sscanf(line, "%lx-%lx %4s %lx %5s %lu %255[^\n]",
        &entry.start_addr, &entry.end_addr, entry.permissions,
        &entry.offset, entry.device, &entry.inode, entry.pathname);
    if (ret < 6)
      continue;

    if (!callback(context, &entry))
      break;
  }

  free(line);
  fclose(file);

  return true;
}

