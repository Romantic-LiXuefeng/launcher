/*
 *  Copyright 2017 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#include "sdk/android/src/jni/videocodecinfo.h"

#include "sdk/android/generated_video_jni/jni/VideoCodecInfo_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"

namespace webrtc {
namespace jni {

SdpVideoFormat VideoCodecInfoToSdpVideoFormat(JNIEnv* jni,
                                              const JavaRef<jobject>& j_info) {
  return SdpVideoFormat(
      JavaToStdString(jni, Java_VideoCodecInfo_getName(jni, j_info)),
      JavaToStdMapStrings(jni, Java_VideoCodecInfo_getParams(jni, j_info)));
}

ScopedJavaLocalRef<jobject> SdpVideoFormatToVideoCodecInfo(
    JNIEnv* jni,
    const SdpVideoFormat& format) {
  ScopedJavaLocalRef<jobject> j_params = NativeToJavaMap(
      jni, format.parameters,
      [](JNIEnv* env, const std::pair<std::string, std::string>& entry) {
        return std::make_pair(NativeToJavaString(env, entry.first),
                              NativeToJavaString(env, entry.second));
      });
  return Java_VideoCodecInfo_Constructor(
      jni, NativeToJavaString(jni, format.name), j_params);
}

}  // namespace jni
}  // namespace webrtc
