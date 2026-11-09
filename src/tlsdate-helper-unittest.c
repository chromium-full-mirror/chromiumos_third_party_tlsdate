/*
 * tlsdate-helper-unittest.c - tlsdate-helper unit tests
 * Copyright 2026 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "config.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/compat/clock.h"
#include "src/test_harness.h"
#include "src/tlsdate-helper.h"
#include "src/util.h"

/*
 * Runs check_rtt() in a forked child process so that die() -> exit(1) can be
 * caught without terminating the test harness process (which uses exit code 1
 * to indicate test pass).
 *
 * Returns:
 *   0 if check_rtt() returned normally and populates |*rt_time_ms_out|.
 *   >0 (the child exit status, 1 on die()) if check_rtt() exited early.
 *   -1 on fork/pipe/waitpid error.
 */
static int
run_check_rtt (const struct tlsdate_time *start_time,
               const struct tlsdate_time *end_time,
               uint32_t server_time_s,
               long long *rt_time_ms_out)
{
  int pipefd[2];
  pid_t pid;
  int status = 0;

  if (pipe (pipefd) != 0)
    return -1;

  pid = fork ();
  if (pid < 0)
    {
      close (pipefd[0]);
      close (pipefd[1]);
      return -1;
    }

  if (pid == 0)
    {
      long long rtt;
      close (pipefd[0]);
      rtt = check_rtt (start_time, end_time, server_time_s);
      if (write (pipefd[1], &rtt, sizeof (rtt)) != (ssize_t) sizeof (rtt))
        {
          close (pipefd[1]);
          _exit (2);
        }
      close (pipefd[1]);
      _exit (0);
    }

  close (pipefd[1]);
  if (waitpid (pid, &status, 0) != pid)
    {
      close (pipefd[0]);
      return -1;
    }

  if (!WIFEXITED (status))
    {
      close (pipefd[0]);
      return -1;
    }

  if (WEXITSTATUS (status) == 0)
    {
      long long rtt = -1;
      if (read (pipefd[0], &rtt, sizeof (rtt)) != (ssize_t) sizeof (rtt))
        {
          close (pipefd[0]);
          return -1;
        }
      if (rt_time_ms_out)
        *rt_time_ms_out = rtt;
    }

  close (pipefd[0]);
  return WEXITSTATUS (status);
}

TEST (rtt_below_threshold)
{
  struct tlsdate_time start_time, end_time;
  long long rt_time_ms = -1;

  /* 88 ms handshake RTT. */
  clock_init_time (&start_time, 1793892188, 100000000L);
  clock_init_time (&end_time, 1793892188, 188000000L);
  EXPECT_EQ (0,
             run_check_rtt (&start_time, &end_time, 1793892188, &rt_time_ms));
  EXPECT_EQ (88, rt_time_ms);

  /* 3,000 ms handshake RTT (above the old 2s threshold, within 5s limit). */
  rt_time_ms = -1;
  clock_init_time (&start_time, 1793892188, 0);
  clock_init_time (&end_time, 1793892191, 0);
  EXPECT_EQ (0,
             run_check_rtt (&start_time, &end_time, 1793892188, &rt_time_ms));
  EXPECT_EQ (3000, rt_time_ms);

  /*
   * 999.5 ms RTT across a second boundary where end_time.tv_nsec <
   * start_time.tv_nsec (999,500 us -> 999 ms).
   */
  rt_time_ms = -1;
  clock_init_time (&start_time, 1793892188, 500500000L);
  clock_init_time (&end_time, 1793892189, 500000000L);
  EXPECT_EQ (0,
             run_check_rtt (&start_time, &end_time, 1793892188, &rt_time_ms));
  EXPECT_EQ (999, rt_time_ms);
}

TEST (rtt_at_exact_threshold)
{
  struct tlsdate_time start_time, end_time;
  long long rt_time_ms = -1;

  /* Exactly TLS_RTT_THRESHOLD (5,000 ms) should succeed. */
  clock_init_time (&start_time, 1793930605, 500000000L);
  clock_init_time (&end_time,
                   1793930605 + (TLS_RTT_THRESHOLD / 1000),
                   500000000L);
  EXPECT_EQ (0,
             run_check_rtt (&start_time, &end_time, 1793930606, &rt_time_ms));
  EXPECT_EQ (TLS_RTT_THRESHOLD, rt_time_ms);
}

TEST (rtt_negative_clamped_to_zero)
{
  struct tlsdate_time start_time, end_time;
  long long rt_time_ms = -1;

  /* Non-linear time (end_time < start_time) is clamped to 0 ms. */
  clock_init_time (&start_time, 1793930605, 500000000L);
  clock_init_time (&end_time, 1793930600, 0);
  EXPECT_EQ (0,
             run_check_rtt (&start_time, &end_time, 1793930605, &rt_time_ms));
  EXPECT_EQ (0, rt_time_ms);
}

TEST (rtt_above_threshold_dies)
{
  struct tlsdate_time start_time, end_time;
  long long rt_time_ms = -1;

  /* TLS_RTT_THRESHOLD + 1 ms (5,001 ms) must fail via die(). */
  clock_init_time (&start_time, 1793930605, 500000000L);
  clock_init_time (&end_time,
                   1793930605 + (TLS_RTT_THRESHOLD / 1000),
                   501000000L);
  EXPECT_EQ (1,
             run_check_rtt (&start_time, &end_time, 1793930606, &rt_time_ms));
}

TEST (rtt_suspend_across_handshake_dies)
{
  struct tlsdate_time start_time, end_time;
  long long rt_time_ms = -1;

  /* Reproduces b/582991618: handshake started at 1793930605.623924572 before
   * s2idle suspend and reaped after resume at 1793932837.535605000 (~2231.9s).
   */
  clock_init_time (&start_time, 1793930605, 623924572L);
  clock_init_time (&end_time, 1793932837, 535605000L);
  EXPECT_EQ (1,
             run_check_rtt (&start_time, &end_time, 1793930606, &rt_time_ms));
}

TEST (init_server_time_subsecond_nanoseconds)
{
  struct tlsdate_time server_time;

  /* 88 ms RTT -> half-RTT is 44 ms = 44,000,000 ns. */
  init_server_time (1793892188, 88, &server_time);
  EXPECT_EQ (1793892188, CLOCK_SEC (&server_time));
  EXPECT_EQ (44, CLOCK_MSEC (&server_time));
  EXPECT_EQ (44000, CLOCK_USEC (&server_time));
  EXPECT_EQ (44000000L, CLOCK_NSEC (&server_time));
}

TEST (init_server_time_multi_second_rtt)
{
  struct tlsdate_time server_time;

  /* 5,320 ms RTT -> half-RTT is 2,660 ms = 2 s + 660,000,000 ns. */
  init_server_time (1793892188, 5320, &server_time);
  EXPECT_EQ (1793892190, CLOCK_SEC (&server_time));
  EXPECT_EQ (660, CLOCK_MSEC (&server_time));
  EXPECT_EQ (660000, CLOCK_USEC (&server_time));
  EXPECT_EQ (660000000L, CLOCK_NSEC (&server_time));
}

TEST_HARNESS_MAIN
