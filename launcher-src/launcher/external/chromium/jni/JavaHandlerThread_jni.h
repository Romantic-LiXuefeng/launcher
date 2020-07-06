// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is autogenerated by
//     base/android/jni_generator/jni_generator.py
// For
//     org/chromium/base/JavaHandlerThread

#ifndef org_chromium_base_JavaHandlerThread_JNI
#define org_chromium_base_JavaHandlerThread_JNI

#include <jni.h>

#include "base/android/jni_generator/jni_generator_helper.h"

// Step 1: forward declarations.
JNI_REGISTRATION_EXPORT extern const char
    kClassPath_org_chromium_base_JavaHandlerThread[];
const char kClassPath_org_chromium_base_JavaHandlerThread[] =
    "org/chromium/base/JavaHandlerThread";

// Leaking this jclass as we cannot use LazyInstance from some threads.
JNI_REGISTRATION_EXPORT base::subtle::AtomicWord
    g_org_chromium_base_JavaHandlerThread_clazz = 0;
#ifndef org_chromium_base_JavaHandlerThread_clazz_defined
#define org_chromium_base_JavaHandlerThread_clazz_defined
inline jclass org_chromium_base_JavaHandlerThread_clazz(JNIEnv* env) {
  return base::android::LazyGetClass(env,
      kClassPath_org_chromium_base_JavaHandlerThread,
      &g_org_chromium_base_JavaHandlerThread_clazz);
}
#endif

namespace base {
namespace android {

// Step 2: method stubs.
JNI_GENERATOR_EXPORT void
    Java_org_chromium_base_JavaHandlerThread_nativeInitializeThread(JNIEnv* env,
    jobject jcaller,
    jlong nativeJavaHandlerThread,
    jlong nativeEvent) {
  TRACE_NATIVE_EXECUTION_SCOPED("InitializeThread");
  JavaHandlerThread* native =
      reinterpret_cast<JavaHandlerThread*>(nativeJavaHandlerThread);
  CHECK_NATIVE_PTR(env, jcaller, native, "InitializeThread");
  return native->InitializeThread(env, base::android::JavaParamRef<jobject>(env,
      jcaller), nativeEvent);
}

JNI_GENERATOR_EXPORT void
    Java_org_chromium_base_JavaHandlerThread_nativeStopThread(JNIEnv* env,
    jobject jcaller,
    jlong nativeJavaHandlerThread) {
  TRACE_NATIVE_EXECUTION_SCOPED("StopThread");
  JavaHandlerThread* native =
      reinterpret_cast<JavaHandlerThread*>(nativeJavaHandlerThread);
  CHECK_NATIVE_PTR(env, jcaller, native, "StopThread");
  return native->StopThread(env, base::android::JavaParamRef<jobject>(env,
      jcaller));
}

JNI_GENERATOR_EXPORT void
    Java_org_chromium_base_JavaHandlerThread_nativeOnLooperStopped(JNIEnv* env,
    jobject jcaller,
    jlong nativeJavaHandlerThread) {
  TRACE_NATIVE_EXECUTION_SCOPED("OnLooperStopped");
  JavaHandlerThread* native =
      reinterpret_cast<JavaHandlerThread*>(nativeJavaHandlerThread);
  CHECK_NATIVE_PTR(env, jcaller, native, "OnLooperStopped");
  return native->OnLooperStopped(env, base::android::JavaParamRef<jobject>(env,
      jcaller));
}

static base::subtle::AtomicWord g_org_chromium_base_JavaHandlerThread_create =
    0;
static base::android::ScopedJavaLocalRef<jobject>
    Java_JavaHandlerThread_create(JNIEnv* env, const
    base::android::JavaRef<jstring>& name) {
  CHECK_CLAZZ(env, org_chromium_base_JavaHandlerThread_clazz(env),
      org_chromium_base_JavaHandlerThread_clazz(env), NULL);
  jmethodID method_id =
      base::android::MethodID::LazyGet<
      base::android::MethodID::TYPE_STATIC>(
      env, org_chromium_base_JavaHandlerThread_clazz(env),
      "create",
"("
"Ljava/lang/String;"
")"
"Lorg/chromium/base/JavaHandlerThread;",
      &g_org_chromium_base_JavaHandlerThread_create);

  jobject ret =
env->CallStaticObjectMethod(org_chromium_base_JavaHandlerThread_clazz(env),
          method_id, name.obj());
  jni_generator::CheckException(env);
  return base::android::ScopedJavaLocalRef<jobject>(env, ret);
}

static base::subtle::AtomicWord
    g_org_chromium_base_JavaHandlerThread_startAndInitialize = 0;
static void Java_JavaHandlerThread_startAndInitialize(JNIEnv* env, const
    base::android::JavaRef<jobject>& obj, jlong nativeThread,
    jlong nativeEvent) {
  CHECK_CLAZZ(env, obj.obj(),
      org_chromium_base_JavaHandlerThread_clazz(env));
  jmethodID method_id =
      base::android::MethodID::LazyGet<
      base::android::MethodID::TYPE_INSTANCE>(
      env, org_chromium_base_JavaHandlerThread_clazz(env),
      "startAndInitialize",
"("
"J"
"J"
")"
"V",
      &g_org_chromium_base_JavaHandlerThread_startAndInitialize);

     env->CallVoidMethod(obj.obj(),
          method_id, nativeThread, nativeEvent);
  jni_generator::CheckException(env);
}

static base::subtle::AtomicWord
    g_org_chromium_base_JavaHandlerThread_stopOnThread = 0;
static void Java_JavaHandlerThread_stopOnThread(JNIEnv* env, const
    base::android::JavaRef<jobject>& obj, jlong nativeThread) {
  CHECK_CLAZZ(env, obj.obj(),
      org_chromium_base_JavaHandlerThread_clazz(env));
  jmethodID method_id =
      base::android::MethodID::LazyGet<
      base::android::MethodID::TYPE_INSTANCE>(
      env, org_chromium_base_JavaHandlerThread_clazz(env),
      "stopOnThread",
"("
"J"
")"
"V",
      &g_org_chromium_base_JavaHandlerThread_stopOnThread);

     env->CallVoidMethod(obj.obj(),
          method_id, nativeThread);
  jni_generator::CheckException(env);
}

static base::subtle::AtomicWord g_org_chromium_base_JavaHandlerThread_joinThread
    = 0;
static void Java_JavaHandlerThread_joinThread(JNIEnv* env, const
    base::android::JavaRef<jobject>& obj) {
  CHECK_CLAZZ(env, obj.obj(),
      org_chromium_base_JavaHandlerThread_clazz(env));
  jmethodID method_id =
      base::android::MethodID::LazyGet<
      base::android::MethodID::TYPE_INSTANCE>(
      env, org_chromium_base_JavaHandlerThread_clazz(env),
      "joinThread",
"("
")"
"V",
      &g_org_chromium_base_JavaHandlerThread_joinThread);

     env->CallVoidMethod(obj.obj(),
          method_id);
  jni_generator::CheckException(env);
}

static base::subtle::AtomicWord g_org_chromium_base_JavaHandlerThread_stop = 0;
static void Java_JavaHandlerThread_stop(JNIEnv* env, const
    base::android::JavaRef<jobject>& obj, jlong nativeThread) {
  CHECK_CLAZZ(env, obj.obj(),
      org_chromium_base_JavaHandlerThread_clazz(env));
  jmethodID method_id =
      base::android::MethodID::LazyGet<
      base::android::MethodID::TYPE_INSTANCE>(
      env, org_chromium_base_JavaHandlerThread_clazz(env),
      "stop",
"("
"J"
")"
"V",
      &g_org_chromium_base_JavaHandlerThread_stop);

     env->CallVoidMethod(obj.obj(),
          method_id, nativeThread);
  jni_generator::CheckException(env);
}

static base::subtle::AtomicWord g_org_chromium_base_JavaHandlerThread_isAlive =
    0;
static jboolean Java_JavaHandlerThread_isAlive(JNIEnv* env, const
    base::android::JavaRef<jobject>& obj) {
  CHECK_CLAZZ(env, obj.obj(),
      org_chromium_base_JavaHandlerThread_clazz(env), false);
  jmethodID method_id =
      base::android::MethodID::LazyGet<
      base::android::MethodID::TYPE_INSTANCE>(
      env, org_chromium_base_JavaHandlerThread_clazz(env),
      "isAlive",
"("
")"
"Z",
      &g_org_chromium_base_JavaHandlerThread_isAlive);

  jboolean ret =
      env->CallBooleanMethod(obj.obj(),
          method_id);
  jni_generator::CheckException(env);
  return ret;
}

static base::subtle::AtomicWord
    g_org_chromium_base_JavaHandlerThread_listenForUncaughtExceptionsForTesting
    = 0;
static void Java_JavaHandlerThread_listenForUncaughtExceptionsForTesting(JNIEnv*
    env, const base::android::JavaRef<jobject>& obj) {
  CHECK_CLAZZ(env, obj.obj(),
      org_chromium_base_JavaHandlerThread_clazz(env));
  jmethodID method_id =
      base::android::MethodID::LazyGet<
      base::android::MethodID::TYPE_INSTANCE>(
      env, org_chromium_base_JavaHandlerThread_clazz(env),
      "listenForUncaughtExceptionsForTesting",
"("
")"
"V",
&g_org_chromium_base_JavaHandlerThread_listenForUncaughtExceptionsForTesting);

     env->CallVoidMethod(obj.obj(),
          method_id);
  jni_generator::CheckException(env);
}

static base::subtle::AtomicWord
    g_org_chromium_base_JavaHandlerThread_getUncaughtExceptionIfAny = 0;
static base::android::ScopedJavaLocalRef<jthrowable>
    Java_JavaHandlerThread_getUncaughtExceptionIfAny(JNIEnv* env, const
    base::android::JavaRef<jobject>& obj) {
  CHECK_CLAZZ(env, obj.obj(),
      org_chromium_base_JavaHandlerThread_clazz(env), NULL);
  jmethodID method_id =
      base::android::MethodID::LazyGet<
      base::android::MethodID::TYPE_INSTANCE>(
      env, org_chromium_base_JavaHandlerThread_clazz(env),
      "getUncaughtExceptionIfAny",
"("
")"
"Ljava/lang/Throwable;",
      &g_org_chromium_base_JavaHandlerThread_getUncaughtExceptionIfAny);

  jthrowable ret =
      static_cast<jthrowable>(env->CallObjectMethod(obj.obj(),
          method_id));
  jni_generator::CheckException(env);
  return base::android::ScopedJavaLocalRef<jthrowable>(env, ret);
}

}  // namespace android
}  // namespace base

#endif  // org_chromium_base_JavaHandlerThread_JNI
