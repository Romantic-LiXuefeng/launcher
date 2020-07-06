// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/base_export.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include <SDL_log.h>

namespace base {

// content_uri_utils.cc
bool ContentUriExists(const FilePath& content_uri) {
  return false;
}

File OpenContentUriForRead(const FilePath& content_uri) {
  int fd = -1;
  if (fd < 0)
    return File();
  // return File(fd);
  return File();
}

std::string GetContentUriMimeType(const FilePath& content_uri) {
  
  return std::string();
}

namespace android {
// path_utils.cc
bool GetDataDirectory(FilePath* result) {
	SDL_Log("GetDataDirectory()------E");
  FilePath data_path("/data/user/0/com.leagor.iaccess/app_null");
  *result = data_path;
  return true;
}

bool GetCacheDirectory(FilePath* result) {
	SDL_Log("GetCacheDirectory()------E");
  FilePath cache_path("/data/user/0/com.leagor.iaccess/cache");
  *result = cache_path;
  return true;
}

bool GetThumbnailCacheDirectory(FilePath* result) {
	SDL_Log("GetThumbnailCacheDirectory()------E");
  FilePath thumbnail_cache_path("/data/user/0/com.leagor.iaccess/app_textures");
  *result = thumbnail_cache_path;
  return true;
}

bool GetDownloadsDirectory(FilePath* result) {
	SDL_Log("GetDownloadsDirectory()------E");
  FilePath downloads_path("/storage/emulated/0/Download");
  *result = downloads_path;
  return true;
}

bool GetNativeLibraryDirectory(FilePath* result) {
  FilePath library_path("/data/app/com.leagor.iaccess-1/lib/arm");
  *result = library_path;
  return true;
}

bool GetExternalStorageDirectory(FilePath* result) {
	SDL_Log("GetExternalStorageDirectory()------E");
  FilePath storage_path("/storage/emulated/0");
  *result = storage_path;
  return true;
}

// sys_utils.cc
class BASE_EXPORT SysUtils {
 public:
  // Returns true iff this is a low-end device.
  static bool IsLowEndDeviceFromJni();
  // Returns true if system has low available memory.
  static bool IsCurrentlyLowMemory();
};

bool SysUtils::IsLowEndDeviceFromJni() {
  return false;
}

bool SysUtils::IsCurrentlyLowMemory() {
  return false;
}

}  // namespace android
}  // namespace base
