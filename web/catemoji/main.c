#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/sendfile.h>
#include <unistd.h>

static char buf[4096], *path;
static size_t buf_start, buf_end, file_len, path_len;
static int fd;

/**
 * Ensures buf has at least `min_length` bytes available. On error, returns -1
 * and sets errno.
 */
static int try_fill_buf(size_t min_length) {
  assert(min_length <= 4096);
  size_t wanted_end = buf_start + min_length;
  if (wanted_end > 4096) {
    memmove(&buf[0], &buf[buf_start], buf_end - buf_start);
    buf_end -= buf_start;
    buf_start = 0;
    wanted_end = min_length;
  }

  while (buf_end < wanted_end) {
    ssize_t ret = read(STDIN_FILENO, &buf[buf_end], wanted_end - buf_end);
    if (ret == 0) {
      errno = EAGAIN;
      return -1;
    }
    if (ret < 0)
      return -1;
    buf_end += ret;
  }
  return 0;
}

/**
 * Ensures buf has at least `min_length` bytes available. On error, exits.
 */
static void fill_buf(size_t min_length) {
  if (try_fill_buf(min_length) == -1)
    perror("read fill_buf"), exit(111);
}

/**
 * Makes standard input non-blocking.
 */
static void stdin_nonblocking(void) {
  int flags = fcntl(STDIN_FILENO, F_GETFL);
  if (flags == -1)
    perror("fcntl F_GETFL stdin_nonblocking"), exit(111);
  if (fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == -1)
    perror("fcntl F_SETFL stdin_nonblocking"), exit(111);
}

/**
 * Makes standard input blocking.
 */
static void stdin_blocking(void) {
  int flags = fcntl(STDIN_FILENO, F_GETFL);
  if (flags == -1)
    perror("fcntl F_GETFL stdin_blocking"), exit(111);
  if (fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK) == -1)
    perror("fcntl F_SETFL stdin_blocking"), exit(111);
}

/**
 * Sends an HTTP error, then exits.
 */
static noreturn void http_error(int status, const char *name,
                                const char *extra_header,
                                const char *extra_body) {
  if (!extra_header)
    extra_header = "";
  if (!extra_body)
    extra_body = "";
  size_t content_length = 10 + strlen(name) + strlen(extra_body);
  printf("HTTP/1.1 %d %s\r\n"
         "Content-Length: %zu\r\n"
         "Content-Type: text/html\r\n"
         "Server: catemoji\r\n"
         "%s"
         "\r\n"
         "<h1>%s</h1>\n%s",
         status, name, content_length, extra_header, name, extra_body);
  exit(0);
}

/**
 * Reads into the buffer until it contains the given substring.
 */
__attribute__((nonnull(1), null_terminated_string_arg(1))) static size_t
fill_buf_until(char *str) {
  char *ret;
  size_t len = strlen(str);

  if ((ret = memmem(&buf[buf_start], buf_end - buf_start, str, len)))
    return ret - &buf[buf_start];
  do {
    // Read one byte.
    fill_buf((buf_end - buf_start) + 1);

    // Read more bytes, because we probably did get more than one.
    stdin_nonblocking();
    if (try_fill_buf(4096) == -1)
      if (errno != EAGAIN)
        perror("read fill_buf_until"), exit(111);
    stdin_blocking();

    // If we found the string, we're done.
    if ((ret = memmem(&buf[buf_start], buf_end - buf_start, str, len)))
      return ret - &buf[buf_start];

    if (buf_end - buf_start == 4096)
      // We filled up the buffer and didn't find anything. Write a 400.
      http_error(400, "Bad Request", NULL, NULL);
  } while (1);
}

static bool decode_nybble(char ch, uint8_t *out) {
  if ('0' <= ch && ch <= '9')
    *out = ch - '0';
  else if ('A' <= ch && ch <= 'F')
    *out = 10 + ch - 'A';
  else if ('a' <= ch && ch <= 'f')
    *out = 10 + ch - 'a';
  else
    return true;
  return false;
}

static bool unescape_path(void) {
  size_t buf_len = 0, buf_cap = 4096;
  char *buf = malloc(buf_cap), ch;
  uint8_t hi, lo;

  while (path_len--) {
    if ((ch = *path++) == '%') {
      if (path_len < 2)
        return true;
      path_len -= 2;
      if (decode_nybble(*path++, &hi) || decode_nybble(*path++, &lo))
        return true;
      ch = hi << 4 | lo;
    }
    buf[buf_len++] = ch;
    if (buf_cap == buf_len)
      buf = realloc(buf, buf_cap <<= 1);
  }
  path = buf;
  path_len = buf_len;
  path[path_len] = '\0';
  return false;
}

static void sanitize_path(void) {
  char *end;
  size_t path_component_len;
  char *ptr = path;
  size_t ptr_len = path_len;

  while (ptr_len) {
    // Invariant: ptr points to the start of a path component.
    end = memchr(ptr, '/', ptr_len);
    path_component_len = end ? end - ptr : ptr_len;
    if (path_component_len == 2 && memcmp(ptr, "..", 2) == 0)
      http_error(451, "Unavailable For Legal Reasons", NULL,
                 "Path traversal attack detected\n");

    ptr = end;
    ptr_len -= path_component_len;
    if (end) {
      ptr++;
      ptr_len--;
    }
  }
}

static bool path_utf8_strlen(size_t *out_len) {
  char *buf = malloc(path_len + 1), *ptr = path, ch;
  size_t buf_len = 0, ptr_len = path_len;
  uint32_t usv, mask;
  int utf8_cont_len;

  while (ptr_len--) {
    // Decode a USV from UTF-8.
    usv = (uint8_t)*ptr++;
    if ((usv & 0xf8) == (mask = 0xf8))
      return true;
    else if ((usv & 0xf0) == (mask = 0xf0))
      utf8_cont_len = 3;
    else if ((usv & 0xe0) == (mask = 0xe0))
      utf8_cont_len = 2;
    else if ((usv & 0xc0) == (mask = 0xc0))
      utf8_cont_len = 1;
    else if ((usv & 0x80) == (mask = 0x80))
      return true;
    else
      mask = utf8_cont_len = 0;
    usv &= ~mask;
    if (utf8_cont_len > ptr_len)
      return true;
    ptr_len -= utf8_cont_len;
    while (utf8_cont_len--) {
      ch = *ptr++;
      if ((ch & 0xc0) == 0xc0)
        return true;
      else if (ch & 0x80)
        ;
      else
        return true;

      usv <<= 6;
      usv |= (uint32_t)ch & 0x3f;
    }

    if (usv < 0x80)
      buf[buf_len++] = usv;
    else if (usv < 0x800)
      buf[buf_len++] = 0xc0 | ((usv >> 6) & 0x1f),
      buf[buf_len++] = 0x80 | (usv & 0x3f);
    else if (usv < 0x10000)
      buf[buf_len++] = 0xe0 | ((usv >> 12) & 0x0f),
      buf[buf_len++] = 0x80 | ((usv >> 6) & 0x3f),
      buf[buf_len++] = 0x80 | (usv & 0x3f);
    else if (usv < 0x110000)
      buf[buf_len++] = 0xf0 | ((usv >> 18) & 0x07),
      buf[buf_len++] = 0x80 | ((usv >> 12) & 0x3f),
      buf[buf_len++] = 0x80 | ((usv >> 6) & 0x3f),
      buf[buf_len++] = 0x80 | (usv & 0x3f);
    else
      return true;
  }
  path = buf;
  *out_len = buf_len;
  buf[buf_len] = '\0';
  return false;
}

int main(void) {
  // Set a timeout of 5 seconds.
  alarm(5);

  // Check the HTTP method.
  fill_buf(5);
  if (memcmp(&buf[buf_start], "GET /", 5) != 0)
    http_error(405, "Method Not Allowed", "Allow: GET\r\n", NULL);
  buf_start += 5;

  // Read the path.
  path_len = fill_buf_until(" ");
  path = memcpy(malloc(path_len + 1), &buf[buf_start], path_len);
  path[path_len] = '\0';
  buf_start += path_len + 1;

  // Check the HTTP version.
  fill_buf(10);
  if (memcmp(&buf[buf_start], "HTTP/1.1\r\n", 10) != 0)
    http_error(505, "HTTP Version Not Supported", NULL, NULL);
  buf_start += 10;

  // Skip headers.
  for (;;) {
    fill_buf(2);
    if (memcmp(&buf[buf_start], "\r\n", 2) == 0) {
      buf_start += 2;
      break;
    }

    buf_start += fill_buf_until(":") + 1;
    while (fill_buf(1), (buf[buf_start] == '\t' || buf[buf_start] == ' '))
      buf_start++;
    buf_start += fill_buf_until("\r\n") + 2;
  }

  // At this point, we should be done parsing the HTTP request.

  // Check if the path started with `/`.
  if (path_len && path[0] == '/')
    http_error(451, "Unavailable For Legal Reasons", NULL,
               "Path traversal attack detected\n");

  // Unescape the path.
  if (unescape_path())
    http_error(451, "Unavailable For Legal Reasons", NULL,
               "Invalid path percent-encoding\n");

  // Check if any path component is `..`.
  sanitize_path();

  // Check if the path is too long.
  if (path_utf8_strlen(&path_len))
    http_error(451, "Unavailable For Legal Reasons", NULL, "Invalid Unicode\n");

  if (path_len > 255)
    http_error(451, "Unavailable For Legal Reasons", NULL, "Path too long\n");
  else if (path_len == 0)
    path = "index.html";

  if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
    http_error(404, "Not Found", NULL, NULL);

  if ((file_len = lseek(fd, 0, SEEK_END)) == -1)
    perror("lseek"), exit(111);
  if (lseek(fd, 0, SEEK_SET) == -1)
    perror("lseek"), exit(111);

  printf("HTTP/1.1 200 OK\r\n"
         "Content-Length: %zu\r\n"
         "Server: catemoji\r\n"
         "\r\n",
         file_len);
  fflush(stdout);

  while (file_len) {
    ssize_t ret = sendfile(STDOUT_FILENO, fd, NULL, file_len);
    file_len -= ret;
    if (ret == 0) {
      fprintf(stderr, "sendfile EOF\n"), exit(111);
    } else if (ret == -1) {
      if (errno == ENOTSUP || errno == EINVAL)
        break;
      else
        perror("sendfile"), exit(111);
    }
  }
  while (file_len) {
    ssize_t ret = read(fd, buf, file_len > 4096 ? 4096 : file_len);
    if (ret == 0)
      fprintf(stderr, "read EOF\n"), exit(111);
    else if (ret == -1)
      perror("read"), exit(111);
    file_len -= ret;

    size_t i = 0;
    while (i < ret) {
      ssize_t ret2 = write(STDOUT_FILENO, &buf[i], ret);
      if (ret2 == 0)
        fprintf(stderr, "write EOF\n"), exit(111);
      else if (ret2 == -1)
        perror("write"), exit(111);
      i += ret2;
    }
  }

  return 0;
}
