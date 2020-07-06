#ifndef GAME_CONFIG_H_INCLUDED
#define GAME_CONFIG_H_INCLUDED

#include "preferences.hpp"
#include "sdl_utils.hpp"

#define DEFAULT_SUPRESS_THRESHOLD		1800 // 30 minite

namespace game_config {

extern std::map<int, std::string> suppress_thresholds;
extern version_info kosapi_ver;
}

namespace preferences {

int suppressthreshold();
void set_suppressthreshold(int value);

}

#endif

