/*
 *  Copyright (c) 2013 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#include <SDL_log.h>
#include <utility>

#include <kosapi/sys.h>

#include "serialization/string_utils.hpp"
#include "thread.hpp"
#include "wml_exception.hpp"
#include "filesystem.hpp"
#include "rose_config.hpp"
#include "base_instance.hpp"
#include "rtc_base/bind.h"

#ifndef _WIN32
#error "This file is impletement of libkosapi.so on windows!"
#endif

void kosGetVersion(char* ver, int max_bytes)
{
    strcpy(ver, "0.0.1-20200705");
}

uint32_t kosSendInput(uint32_t input_count, KosInput* inputs)
{
    VALIDATE(input_count > 0 && inputs != nullptr, null_str);
    INPUT* inputs_dst = (INPUT*)malloc(sizeof(INPUT) * input_count);
    memset(inputs_dst, 0, sizeof(INPUT) * input_count);

    int width = 1920;
    int height = 1080;
    for (int n = 0; n < (int)input_count; n ++) {
        KosInput* src = inputs + n;
        INPUT* dst = inputs_dst + n;
        if (src->type == KOS_INPUT_MOUSE) {
            dst->type = INPUT_MOUSE;
		    dst->mi.dx = (int)((float)src->u.mi.dx * (65535.0f / width));
		    dst->mi.dy = (int)((float)src->u.mi.dy * (65535.0f / height));
            dst->mi.mouseData = src->u.mi.mouse_data;
            dst->mi.dwFlags = src->u.mi.flags;
            dst->mi.time = src->u.mi.time;

        } else if (src->type == KOS_INPUT_KEYBOARD) {
            dst->type = INPUT_KEYBOARD;
            dst->ki.wVk = src->u.ki.virtual_key;
            dst->ki.wScan = src->u.ki.scan_code;
            dst->ki.dwFlags = src->u.ki.flags;
            dst->ki.time = src->u.ki.time;
        }
    }
    uint32_t ret = SendInput(input_count, inputs_dst, sizeof(INPUT));
    free(inputs_dst);
    return ret;
}