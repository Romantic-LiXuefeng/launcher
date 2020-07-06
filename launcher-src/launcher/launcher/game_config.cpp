#define GETTEXT_DOMAIN "launcher-lib"

#include "global.hpp"
#include "game_config.hpp"
#include "version.hpp"

#include <sstream>
#include <iomanip>
#include <boost/bind.hpp>

namespace game_config {

std::map<int, std::string> suppress_thresholds;
version_info kosapi_ver;

}

namespace preferences {

int suppressthreshold()
{
	int value = preferences::get_int("suppressthreshold", DEFAULT_SUPRESS_THRESHOLD);
	if (game_config::suppress_thresholds.count(value) == 0) {
		value = DEFAULT_SUPRESS_THRESHOLD;
	}
	return value;
}

void set_suppressthreshold(int value)
{
	VALIDATE(game_config::suppress_thresholds.count(value) != 0, null_str);
	if (suppressthreshold() != value) {
		preferences::set_int("suppressthreshold", value);
		preferences::write_preferences();
	}
}

}
