/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/String.h>

#ifdef __linux__
#include <exception>
#include <string>
#include <string_view>
#endif

#include "watchman/Connect.h"
#include "watchman/Logging.h"
#include "watchman/PDU.h"
#include "watchman/SanityCheck.h"
#include "watchman/Shutdown.h"
#include "watchman/fs/FileSystem.h"
#include "watchman/watchman_stream.h"

namespace watchman {

#ifdef __linux__
std::optional<FileIdentity> getIdentityForPath(const char* path) {
  try {
    auto options = OpenFileHandleOptions::queryFileInfo();
    options.followSymlinks = true;
    options.strictNameChecks = false;
    const auto info = openFileHandle(path, options).getInfo();
    return FileIdentity{
        static_cast<uint64_t>(info.dev), static_cast<uint64_t>(info.ino)};
  } catch (const std::exception& error) {
    log(DBG, "unable to inspect ", path, ": ", error.what(), "\n");
    return std::nullopt;
  }
}

ExecutableChange checkExecutableChange(
    const FileIdentity& running,
    const char* path) {
  auto installed = getIdentityForPath(path);
  if (!installed) {
    return ExecutableChange::Unknown;
  }
  return *installed == running ? ExecutableChange::Unchanged
                               : ExecutableChange::Changed;
}
#endif

namespace {

#ifdef __linux__
constexpr const char* kProcSelfExe = "/proc/self/exe";
constexpr std::string_view kDeletedSuffix = " (deleted)";

/**
 * Filesystem location this process was executed from.
 *
 * A special case when RPM upgrade happens when watchman starts:
 * The kernel marks the executable location `" (deleted)"` once the
 * old file is unlinked so the marker is stripped.
 */
std::optional<std::string> getExecutablePathToWatch() {
  try {
    auto path = readSymbolicLink(kProcSelfExe).string();
    if (path.ends_with(kDeletedSuffix)) {
      path.resize(path.size() - kDeletedSuffix.size());
    }
    return path;
  } catch (const std::exception& error) {
    log(DBG, "unable to resolve /proc/self/exe: ", error.what(), "\n");
    return std::nullopt;
  }
}

bool waitForShutdown(std::chrono::seconds duration) {
  const auto deadline = std::chrono::steady_clock::now() + duration;
  while (!w_is_stopping() && std::chrono::steady_clock::now() < deadline) {
    /* sleep override */
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  return w_is_stopping();
}

void binaryChangeMonitorThread(
    FileIdentity running,
    std::string path,
    std::chrono::seconds checkInterval) noexcept {
  w_set_thread_name("binarychange");

  log(DBG, "starting binary change monitor for ", path, "\n");
  while (!waitForShutdown(checkInterval)) {
    const auto change = checkExecutableChange(running, path.c_str());
    if (change == ExecutableChange::Unknown) {
      log(DBG, "unable to inspect watchman binary at ", path, "\n");
      continue;
    }
    if (change == ExecutableChange::Unchanged) {
      continue;
    }

    log(ERR, "watchman binary changed at ", path, "; shutting down\n");
    w_request_shutdown();
    break;
  }
  log(DBG, "done with binary change monitor\n");
}
#endif

// Work-around decodeNext which implictly resets to non-blocking
std::optional<json_ref>
decodeNext(watchman_stream* client, PduBuffer& buf, json_error_t& jerr) {
  client->setNonBlock(false);
  return buf.decodeNext(client, &jerr);
}

/* Periodically connect to our endpoint and verify that we're talking
 * to ourselves.  This is normally a sign of madness, but if we don't
 * get an answer, or get a reply from someone else, we know things
 * are bad; someone removed our socket file or there was some kind of
 * race condition that resulted in multiple instances starting up.
 */
void check_my_sock(watchman_stream* client) {
  auto cmd = json_array({typed_string_to_json("get-pid", W_STRING_UNICODE)});
  PduBuffer buf;
  json_error_t jerr;
  pid_t my_pid = ::getpid();

  auto res = buf.pduEncodeToStream(PduFormat{is_bser, 0}, cmd, client);
  if (res.hasError()) {
    log(watchman::FATAL,
        "Failed to send get-pid PDU: ",
        folly::errnoStr(res.error()),
        "\n");
    /* NOTREACHED */
  }

  buf.clear();
  auto result = decodeNext(client, buf, jerr);
  if (!result) {
    log(watchman::FATAL,
        "Failed to decode get-pid response: ",
        jerr.text,
        " ",
        folly::errnoStr(errno),
        "\n");
    /* NOTREACHED */
  }

  auto pid = result->get_optional("pid");
  if (!pid) {
    log(watchman::FATAL,
        "Failed to get pid from get-pid response: ",
        jerr.text,
        "\n");
    /* NOTREACHED */
  }
  auto remote_pid = pid->asInt();

  if (remote_pid != my_pid) {
    log(watchman::FATAL,
        "remote pid from get-pid ",
        long(remote_pid),
        " doesn't match my pid (",
        (long)my_pid,
        "\n");
    /* NOTREACHED */
  }
}

void sanityCheckThread() noexcept {
  w_set_thread_name("sanitychecks");
  auto lastCheck = std::chrono::steady_clock::now();
  auto interval = std::chrono::minutes(1);

  log(ERR, "starting sanityCheckThread\n");
  // we want to try the checks in here once per minute, but since
  // this is mildly ghetto we don't have a way to directly signal
  // this thread when we're shutting down.  So we sleep for a second
  // at a time and then check to see if a shutdown is in progress
  // so that we can shutdown with a slightly lower latency than
  // if we were to sleep for a minute at a time.
  while (!w_is_stopping()) {
    auto now = std::chrono::steady_clock::now();
    if (now - lastCheck < interval) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      continue;
    }

    lastCheck = now;
    log(DBG, "running sanity checks\n");

    auto client = w_stm_connect(6000);
    if (client.hasError()) {
      log(watchman::FATAL,
          "Failed to connect to myself for sanity check: ",
          folly::errnoStr(client.error()),
          "\n");
      /* NOTREACHED */
    }
    check_my_sock(client.value().get());
  }
  log(ERR, "done with sanityCheckThread\n");
}
} // namespace

#ifdef __linux__
std::thread startBinaryChangeMonitorThread(std::chrono::seconds checkInterval) {
  // Identify the running image through the magic link, not through the path it
  // resolves to: it names the inode this process is executing even after that
  // inode is unlinked.
  auto running = getIdentityForPath(kProcSelfExe);
  auto path = getExecutablePathToWatch();
  if (!running || !path) {
    log(ERR, "binary change monitor could not identify the executable\n");
    return {};
  }

  return std::thread{
      binaryChangeMonitorThread, *running, std::move(*path), checkInterval};
}
#endif

void startSanityCheckThread() {
  // The blocking pipe reads we use on win32 can cause us to get blocked
  // forever running the sanity checks, so skip this on win32
#ifndef _WIN32
  std::thread thr(sanityCheckThread);
  thr.detach();
#endif
}
} // namespace watchman
