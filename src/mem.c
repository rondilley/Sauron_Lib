/****
 *
 * Memory functions
 *
 * Copyright (c) 2006-2025, Ron Dilley
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 ****/

/****
 *
 * includes
 *
 ****/

#include "mem.h"

/****
 *
 * local variables
 *
 ****/

/****
 *
 * external global variables
 *
 ****/

extern int quit;

/****
 *
 * global variables
 *
 ****/

#ifdef MEM_DEBUG
PRIVATE struct Mem_s *head;
PRIVATE struct Mem_s *tail;
#endif

/****
 *
 * functions
 *
 ****/

/****
 *
 * Safely concatenate command line arguments with overflow protection
 *
 ****/

PUBLIC char *copy_argv(char *argv[])
{
  PRIVATE char **arg;
  PRIVATE char *buf;
  PRIVATE size_t total_length = 0;

  for (arg = argv; *arg != NULL; arg++)
  {
    size_t arg_len = strlen(*arg);
    if (total_length > SIZE_MAX - arg_len - 1)
    {
      fprintf(stderr, "ERR - Integer overflow in copy_argv: argument too long\n");
      return NULL;
    }
    total_length += (arg_len + 1);
  }

  if (total_length == 0)
    return NULL;

  if (total_length > SIZE_MAX - 1)
  {
    fprintf(stderr, "ERR - Integer overflow in copy_argv (null terminator)\n");
    return NULL;
  }
  total_length++;

  buf = (char *)XMALLOC(sizeof(char) * total_length);

  *buf = 0;
  for (arg = argv; *arg != NULL; arg++)
  {
#ifdef HAVE_STRLCAT
    strlcat(buf, *arg, total_length);
    strlcat(buf, " ", total_length);
#else
    size_t current_len = strlen(buf);
    size_t remaining = total_length - current_len - 1;
    strncat(buf, *arg, remaining);
    current_len = strlen(buf);
    remaining = total_length - current_len - 1;
    if (remaining > 0)
      strncat(buf, " ", remaining);
#endif
  }

  return buf;
}

/****
 *
 * Debug-aware memory allocation with tracking
 *
 ****/

void *xmalloc_(const int size, const char *filename, const int linenumber)
{
  void *result;
#ifdef MEM_DEBUG
  PRIVATE struct Mem_s *d_result;
#endif

  result = malloc(size);
  if (result == NULL)
  {
    fprintf(stderr, "out of memory (%d at %s:%d)!\n", size, filename,
            linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(EXIT_FAILURE);
  }

#ifdef MEM_DEBUG
  d_result = malloc(sizeof(struct Mem_s));
  if (d_result == NULL)
  {
    fprintf(stderr, "out of memory (%lu at %s:%d)!\n", sizeof(struct Mem_s),
            filename, linenumber);
    XFREE_ALL();
    exit(EXIT_FAILURE);
  }
  bzero(d_result, sizeof(struct Mem_s));

#ifdef SHOW_MEM_DEBUG
  fprintf(stderr, "%p malloc() called from %s:%d (%d bytes)\n", result,
          filename, linenumber, size);
#endif

  if (tail == NULL)
  {
    head = d_result;
    tail = d_result;
  }
  else
  {
    tail->next = d_result;
    d_result->prev = tail;
    d_result->next = NULL;
    tail = d_result;
  }

  d_result->buf_ptr = (void *)result;
  d_result->buf_size = size;
#endif

  bzero(result, size);

#ifdef MEM_DEBUG
  d_result->status = MEM_D_STAT_CLEAN;
#endif

  return result;
}

/****
 *
 * copy from one place to another
 *
 ****/

void *xmemcpy_(void *d_ptr, void *s_ptr, const int size, const char *filename,
               const int linenumber)
{
  void *result;
#ifdef MEM_DEBUG
  PRIVATE struct Mem_s *mem_ptr;
  PRIVATE int source_size;
  PRIVATE int dest_size;
#endif

  if (s_ptr == NULL)
  {
    fprintf(stderr, "memcpy called with NULL source pointer at %s:%d\n",
            filename, linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(1);
  }
  if (d_ptr == NULL)
  {
    fprintf(stderr, "memcpy called with NULL dest pointer at %s:%d\n", filename,
            linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(1);
  }

#ifdef MEM_DEBUG
  source_size = dest_size = 0;
  mem_ptr = head;
  while (mem_ptr != NULL)
  {
    if (mem_ptr->buf_ptr == d_ptr)
    {
      dest_size = mem_ptr->buf_size;
    }
    else if (mem_ptr->buf_ptr == s_ptr)
    {
      source_size = mem_ptr->buf_size;
    }
    mem_ptr = mem_ptr->next;
  }

  if (dest_size > 0)
  {
    if (dest_size < size)
    {
      fprintf(stderr,
              "memcpy called with size (%d) larger than dest buffer %p (%d) at %s:%d\n",
              size, d_ptr, dest_size, filename, linenumber);
      XFREE_ALL();
      exit(EXIT_FAILURE);
    }

    if (source_size > 0)
    {
      if (source_size < size)
      {
        fprintf(stderr,
                "memcpy called with size (%d) larger than source buffer %p (%d) at %s:%d\n",
                size, s_ptr, source_size, filename, linenumber);
        XFREE_ALL();
        exit(EXIT_FAILURE);
      }
    }
#ifdef SHOW_MEM_DEBUG
    else
    {
      fprintf(stderr,
              "%p could not find source buffer at %s:%d called from %s%d\n",
              s_ptr, __FILE__, __LINE__, filename, linenumber);
    }
#endif
  }
#ifdef SHOW_MEM_DEBUG
  else
  {
    fprintf(stderr,
            "%p could not find dest buffer at %s:%d called from %s:%d\n",
            d_ptr, __FILE__, __LINE__, filename, linenumber);
  }
#endif
#endif

  if (s_ptr < d_ptr)
  {
    if (s_ptr + size >= d_ptr)
    {
      result = memmove(d_ptr, s_ptr, size);
    }
    else
    {
      result = memcpy(d_ptr, s_ptr, size);
    }
  }
  else if (s_ptr > d_ptr)
  {
    if (d_ptr + size >= s_ptr)
    {
      result = memmove(d_ptr, s_ptr, size);
    }
    else
    {
      result = memcpy(d_ptr, s_ptr, size);
    }
  }
  else
  {
    fprintf(stderr, "memcpy() called with source == dest at %s:%d\n", filename, linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(1);
  }

#ifdef SHOW_MEM_DEBUG
  fprintf(stderr, "%p memcpy() called from %s:%d (%d bytes)\n", result, filename, linenumber, size);
#endif

  return result;
}

/****
 *
 * set memory area
 *
 ****/

void *xmemset_(void *ptr, const char value, const int size,
               const char *filename, const int linenumber)
{
  void *result;

  if (ptr == NULL)
  {
    fprintf(stderr, "memset() called with NULL ptr at %s:%d\n", filename,
            linenumber);
    quit = TRUE;
    exit(1);
  }

  if (value == 0)
  {
    bzero(ptr, size);
    result = ptr;
  }
  else
  {
    result = memset(ptr, value, size);
  }

#ifdef MEM_DEBUG
  fprintf(stderr, "%p memset %s:%d (%d bytes)\n", result, filename, linenumber, size);
#endif

  return result;
}

/****
 *
 * compare memory
 *
 ****/

int xmemcmp_(const void *s1, const void *s2, size_t n, const char *filename,
             const int linenumber)
{
  int result;

  if (s1 == NULL || s2 == NULL)
  {
    fprintf(stderr, "memcmp() called with NULL ptr at %s:%d\n", filename,
            linenumber);
    quit = TRUE;
    exit(1);
  }

  result = memcmp(s1, s2, n);

#ifdef MEM_DEBUG
  fprintf(stderr, "%p memcmp against %p %s:%d (%ld bytes)\n", s1, s2, filename, linenumber, n);
#endif

  return result;
}

/****
 *
 * Allocate memory with realloc
 *
 ****/

void *xrealloc_(void *ptr, int size, const char *filename, const int linenumber)
{
  void *result;
#ifdef MEM_DEBUG
  PRIVATE struct Mem_s *d_result;
  PRIVATE struct Mem_s *d_ptr;
  PRIVATE int found = FALSE;
#endif

  if (ptr == NULL)
    result = malloc(size);
  else
    result = realloc(ptr, size);

#ifdef MEM_DEBUG
  fprintf(stderr, "%p realloc %s:%d (%d bytes)\n", result, filename, linenumber, size);
#endif

  if (result == NULL)
  {
    fprintf(stderr, "out of memory (%d at %s:%d)!\n", size, filename, linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(EXIT_FAILURE);
  }

#ifdef MEM_DEBUG
  d_ptr = head;
  while (d_ptr != NULL)
  {
    if (d_ptr->buf_ptr == ptr)
    {
      found = TRUE;
      if (d_ptr->prev != NULL)
      {
        d_ptr->prev->next = d_ptr->next;
      }
      else
      {
        head = (void *)d_ptr->next;
      }
      if (d_ptr->next != NULL)
      {
        d_ptr->next->prev = d_ptr->prev;
      }
      else
      {
        tail = d_ptr->prev;
      }
      free(d_ptr);
      d_ptr = NULL;
    }
    else
    {
      d_ptr = d_ptr->next;
    }
  }

  if (!found && ptr != NULL)
  {
    fprintf(stderr, "realloc() called with %p ptr but not found in debug object list at %s:%d\n", ptr, filename, linenumber);
  }

  d_result = malloc(sizeof(struct Mem_s));
  if (d_result == NULL)
  {
    fprintf(stderr, "out of memory (%lu at %s:%d)!\n", sizeof(struct Mem_s), filename, linenumber);
    XFREE_ALL();
    exit(EXIT_FAILURE);
  }
  bzero(d_result, sizeof(struct Mem_s));

#ifdef SHOW_MEM_DEBUG
  fprintf(stderr, "%p realloc() called from %s:%d (%d bytes)\n", result, filename, linenumber, size);
#endif

  if (tail == NULL)
  {
    head = d_result;
    tail = d_result;
  }
  else
  {
    tail->next = d_result;
    d_result->prev = tail;
    d_result->next = NULL;
    tail = d_result;
  }

  d_result->buf_ptr = (void *)result;
  d_result->buf_size = size;
#endif

  return result;
}

/****
 *
 * Free memory
 *
 ****/

void xfree_(void *ptr, const char *filename, const int linenumber)
{
#ifdef MEM_DEBUG
  PRIVATE struct Mem_s *d_ptr;
  PRIVATE int found = FALSE;
  PRIVATE int size = 0;
#endif

  if (ptr == NULL)
  {
    fprintf(stderr, "free() called with NULL ptr at %s:%d\n", filename,
            linenumber);
    exit(1);
  }

#ifdef MEM_DEBUG
  d_ptr = head;
  while (d_ptr != NULL)
  {
    if (d_ptr->buf_ptr == ptr)
    {
      found = TRUE;
      if (d_ptr->prev != NULL)
      {
        d_ptr->prev->next = d_ptr->next;
      }
      else
      {
        head = (void *)d_ptr->next;
      }
      if (d_ptr->next != NULL)
      {
        d_ptr->next->prev = d_ptr->prev;
      }
      else
      {
        tail = d_ptr->prev;
      }
      size = d_ptr->buf_size;
      free(d_ptr);
      d_ptr = NULL;
    }
    else
    {
      d_ptr = d_ptr->next;
    }
  }

  if (!found)
  {
    fprintf(stderr, "free() called with %p ptr but not found in debug object list at %s:%d\n", ptr, filename, linenumber);
  }
#endif

#ifdef SHOW_MEM_DEBUG
#ifdef MEM_DEBUG
  fprintf(stderr, "%p free() called from %s:%d (%d bytes)\n", ptr, filename, linenumber, size);
#else
  fprintf(stderr, "%p free() called from %s:%d\n", ptr, filename, linenumber);
#endif
#endif

  free(ptr);
}

/****
 *
 * free all known buffers
 *
 ****/

#ifdef MEM_DEBUG
void xfree_all_(const char *filename, const int linenumber)
{
  PRIVATE struct Mem_s *d_ptr;

#ifdef SHOW_MEM_DEBUG
  fprintf(stderr, "xfree_all() called from %s:%d\n", filename, linenumber);
#endif

  while ((d_ptr = head) != NULL)
  {
    head = d_ptr->next;
    if (d_ptr->buf_ptr != NULL)
    {
#ifdef SHOW_MEM_DEBUG
      fprintf(stderr, "%p free %s:%d (%d bytes)\n", d_ptr->buf_ptr, filename, linenumber, d_ptr->buf_size);
#endif
      free(d_ptr->buf_ptr);
      d_ptr->buf_ptr = NULL;
    }
    free(d_ptr);
  }

  return;
}
#else
void xfree_all_(const char *filename __attribute__((unused)),
                const int linenumber __attribute__((unused)))
{
  return;
}
#endif

/****
 *
 * Dup a string
 *
 ****/

char *xstrdup_(const char *str, const char *filename __attribute__((unused)),
               const int linenumber __attribute__((unused)))
{
  char *res;

  res = strdup(str);

#ifdef MEM_DEBUG
  fprintf(stderr, "%p malloc %s:%d (%ld) bytes, strdup\n", res, filename, linenumber, strlen(str) + 1);
#endif

  return res;
}

/****
 *
 * grow or shrink an array
 *
 ****/

void xgrow_(void **old, int elementSize, int *oldCount, int newCount,
            char *filename, const int linenumber)
{
  void *tmp;
  int size;

  size = newCount * elementSize;
  if (size == 0)
    tmp = NULL;
  else
  {
    tmp = malloc(size);

#ifdef MEM_DEBUG
    fprintf(stderr, "%p malloc %s:%d (grow)\n", tmp, filename, linenumber);
#endif

    if (tmp == NULL)
    {
      fprintf(stderr, "out of memory (%d at %s:%d)!\n", size, filename, linenumber);
      quit = TRUE;
      exit(1);
    }
    memset(tmp, 0, size);
    if (*oldCount > newCount)
      *oldCount = newCount;
    memcpy(tmp, *old, elementSize * (*oldCount));
  }

  if (*old != NULL)
  {
#ifdef MEM_DEBUG
    fprintf(stderr, "%p free %s:%d (grow)\n", *old, filename, linenumber);
#endif
    free(*old);
  }
  *old = tmp;
  *oldCount = newCount;
}

/****
 *
 * wrapper around strcpy
 *
 ****/

char *xstrcpy_(char *d_ptr, const char *s_ptr, const char *filename,
               const int linenumber)
{
  void *result;
  PRIVATE int size;
#ifdef MEM_DEBUG
  PRIVATE struct Mem_s *mem_ptr;
  PRIVATE int source_size;
  PRIVATE int dest_size;
#endif

  if (s_ptr == NULL)
  {
    fprintf(stderr, "strcpy called with NULL source pointer at %s:%d\n",
            filename, linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(1);
  }
  if (d_ptr == NULL)
  {
    fprintf(stderr, "strcpy called with NULL dest pointer at %s:%d\n", filename,
            linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(1);
  }

  if ((size = (strlen(s_ptr) + 1)) == 0)
  {
#ifdef SHOW_MEM_DEBUG
    fprintf(stderr, "strcpy called with zero length source pointer at %s:%d\n",
            filename, linenumber);
#endif
    d_ptr[0] = 0;
    return d_ptr;
  }

#ifdef MEM_DEBUG
  source_size = dest_size = 0;
  mem_ptr = head;
  while (mem_ptr != NULL)
  {
    if (mem_ptr->buf_ptr == d_ptr)
    {
      dest_size = mem_ptr->buf_size;
    }
    else if (mem_ptr->buf_ptr == s_ptr)
    {
      source_size = mem_ptr->buf_size;
    }
    mem_ptr = mem_ptr->next;
  }

  if (dest_size > 0)
  {
    if (dest_size < size)
    {
      fprintf(stderr,
              "strcpy called with size (%d) larger than dest buffer %p (%d) at %s:%d\n",
              size, d_ptr, dest_size, filename, linenumber);
      XFREE_ALL();
      exit(1);
    }

    if (source_size > 0)
    {
      if (source_size < size)
      {
        fprintf(stderr,
                "strcpy called with size (%d) larger than source buffer %p (%d) at %s:%d\n",
                size, (void *)s_ptr, source_size, filename, linenumber);
        XFREE_ALL();
        exit(1);
      }
    }
#ifdef SHOW_MEM_DEBUG
    else
    {
      fprintf(stderr,
              "%p could not find source buffer at %s:%d called from %s%d\n",
              (void *)s_ptr, __FILE__, __LINE__, filename, linenumber);
    }
#endif
  }
#ifdef SHOW_MEM_DEBUG
  else
  {
    fprintf(stderr,
            "%p could not find dest buffer at %s:%d called from %s:%d\n",
            d_ptr, __FILE__, __LINE__, filename, linenumber);
  }
#endif
#endif

  if (s_ptr < d_ptr)
  {
    if (s_ptr + size >= d_ptr)
    {
      result = memmove(d_ptr, s_ptr, size);
    }
    else
    {
      result = memcpy(d_ptr, s_ptr, size);
    }
  }
  else if (s_ptr > d_ptr)
  {
    if (d_ptr + size >= s_ptr)
    {
      result = memmove(d_ptr, s_ptr, size);
    }
    else
    {
      result = memcpy(d_ptr, s_ptr, size);
    }
  }
  else
  {
    fprintf(stderr, "strcpy() called with source == dest at %s:%d\n", filename, linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(1);
  }
  d_ptr[size - 1] = 0;

#ifdef SHOW_MEM_DEBUG
  fprintf(stderr, "%p strcpy() called from %s:%d (%d bytes)\n", result, filename, linenumber, size);
#endif

  return result;
}

/****
 *
 * wrapper around strncpy
 *
 ****/

char *xstrncpy_(char *d_ptr, const char *s_ptr, const size_t len,
                const char *filename, const int linenumber)
{
  char *result;
  PRIVATE size_t size;
#ifdef MEM_DEBUG
  PRIVATE struct Mem_s *mem_ptr;
  PRIVATE size_t source_size;
  PRIVATE size_t dest_size;
#endif

  if (s_ptr == NULL)
  {
    fprintf(stderr, "strncpy called with NULL source pointer at %s:%d\n", filename, linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(1);
  }

  if (d_ptr == NULL)
  {
    fprintf(stderr, "strncpy called with NULL dest pointer at %s:%d\n", filename, linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(1);
  }

  if (len == 0)
  {
#ifdef SHOW_MEM_DEBUG
    fprintf(stderr, "strncpy called with zero copy length at %s:%d\n", filename, linenumber);
#endif
    d_ptr[0] = 0;
    return d_ptr;
  }

  if ((size = (strnlen(s_ptr, len - 1) + 1)) == 0)
  {
#ifdef SHOW_MEM_DEBUG
    fprintf(stderr, "strncpy called with zero length source pointer at %s:%d\n", filename, linenumber);
#endif
    d_ptr[0] = 0;
    return d_ptr;
  }

#ifdef MEM_DEBUG
  source_size = dest_size = 0;
  mem_ptr = head;
  while (mem_ptr != NULL)
  {
    if (mem_ptr->buf_ptr == d_ptr)
    {
      dest_size = mem_ptr->buf_size;
    }
    else if (mem_ptr->buf_ptr == s_ptr)
    {
      source_size = mem_ptr->buf_size;
    }
    mem_ptr = mem_ptr->next;
  }

  if (dest_size > 0)
  {
    if (dest_size < len)
    {
      fprintf(stderr,
              "strncpy called with size (%lu) larger than dest buffer %p (%lu) at %s:%d\n",
              len, d_ptr, dest_size, filename, linenumber);
      XFREE_ALL();
      exit(1);
    }

    if (source_size > 0)
    {
      if (source_size < len)
      {
        fprintf(stderr,
                "strncpy called with size (%lu) larger than source buffer %p (%lu) at %s:%d\n",
                len, (void *)s_ptr, source_size, filename, linenumber);
        XFREE_ALL();
        exit(1);
      }
    }
#ifdef SHOW_MEM_DEBUG
    else
    {
      fprintf(stderr,
              "%p could not find source buffer at %s:%d called from %s:%d\n",
              (void *)s_ptr, __FILE__, __LINE__, filename, linenumber);
    }
#endif
  }
#ifdef SHOW_MEM_DEBUG
  else
  {
    fprintf(stderr,
            "%p could not find dest buffer at %s:%d called from %s:%d\n",
            d_ptr, __FILE__, __LINE__, filename, linenumber);
  }
#endif
#endif

  if (s_ptr != d_ptr)
    result = strncpy(d_ptr, s_ptr, len);
  else
  {
    fprintf(stderr, "strncpy() called with source == dest at %s:%d\n", filename,
            linenumber);
#ifdef MEM_DEBUG
    XFREE_ALL();
#endif
    exit(1);
  }

  d_ptr[len - 1] = '\0';

#ifdef SHOW_MEM_DEBUG
  fprintf(stderr, "%p strncpy() called from %s:%d (%lu bytes)\n",
          result, filename, linenumber, size);
#endif

  return result;
}
