/* Require Rose v1.0.19 or above. $ */

#define GETTEXT_DOMAIN "launcher-lib"

#include "rdp_server_rose.h"
#include "base_instance.hpp"
#include "gui/dialogs/message.hpp"
#include "gui/dialogs/chat.hpp"
#include "gui/dialogs/home.hpp"
#include "gui/dialogs/explorer.hpp"
#include "gui/widgets/window.hpp"
#include "game_end_exceptions.hpp"
#include "wml_exception.hpp"
#include "gettext.hpp"
#include "loadscreen.hpp"
#include "formula_string_utils.hpp"
#include "help.hpp"
#include "version.hpp"
#include <kosapi/sys.h>

#include "game_config.hpp"

class game_instance: public base_instance
{
public:
	game_instance(rtc::PhysicalSocketServer& ss, int argc, char** argv);
	~game_instance();

	net::trdpd_manager& rdpd_mgr() { return rdpd_mgr_; }
private:
	void app_load_settings_config(const config& cfg) override;
	void app_pre_setmode(tpre_setmode_settings& settings) override;
	void app_load_pb() override;
	void app_handle_clipboard_paste(const std::string& text) override;

private:
	net::trdpd_manager rdpd_mgr_;
};

game_instance::game_instance(rtc::PhysicalSocketServer& ss, int argc, char** argv)
	: base_instance(ss, argc, argv)
{
}

game_instance::~game_instance()
{
}

void game_instance::app_load_settings_config(const config& cfg)
{
	game_config::version = version_info(cfg["version"].str());
	VALIDATE(game_config::version.is_rose_recommended(), null_str);

	char libkosapi_ver[36];
	kosGetVersion(libkosapi_ver, sizeof(libkosapi_ver));
	game_config::kosapi_ver = version_info(libkosapi_ver);
	VALIDATE(game_config::kosapi_ver.is_rose_recommended(), std::string("Error version: ") + game_config::kosapi_ver.str(true));
	const version_info min_libkosapi_ver("0.0.1-20200705");
	if (game_config::kosapi_ver < min_libkosapi_ver) {
		std::stringstream err;
		err << "libkospai's version(" << game_config::kosapi_ver.str(true) << ") must < " << min_libkosapi_ver.str(true);
		VALIDATE(false, err.str());
	}
}

void game_instance::app_pre_setmode(tpre_setmode_settings& settings)
{	
	settings.default_font_size = 18;
	settings.statusbar_visible = false;
	// settings.silent_background = false;
	if (game_config::os == os_windows) {
		settings.min_width = 640;
		settings.min_height = 360;
	}
	// settings.startup_servers = server_httpd;
}

void game_instance::app_load_pb()
{
	utils::string_map symbols;
	symbols["count"] = "1";
	game_config::suppress_thresholds.insert(std::make_pair(1 * 60, vgettext2("$count minutes", symbols)));
	symbols["count"] = "15";
	game_config::suppress_thresholds.insert(std::make_pair(15 * 60, vgettext2("$count minutes", symbols)));
	symbols["count"] = "30";
	game_config::suppress_thresholds.insert(std::make_pair(30 * 60, vgettext2("$count minutes", symbols)));
	symbols["count"] = "1";
	game_config::suppress_thresholds.insert(std::make_pair(1 * 3600, vgettext2("$count hours", symbols)));
	game_config::suppress_thresholds.insert(std::make_pair(nposm, _("No restrictions")));
	VALIDATE(game_config::suppress_thresholds.count(DEFAULT_SUPRESS_THRESHOLD) != 0, null_str);
}

void game_instance::app_handle_clipboard_paste(const std::string& text)
{
	rdpd_mgr_.clipboard_updated(text);
}

extern void SSLServerSocketTest_Handshake();

/**
 * Setups the game environment and enters
 * the titlescreen or game loops.
 */
static int do_gameloop(int argc, char** argv)
{
	rtc::PhysicalSocketServer ss;
	instance_manager<game_instance> manager(ss, argc, argv, "launcher", "#rose");
	game_instance& game = manager.get();

	try {
		if (game_config::os == os_windows) {
			// SSLServerSocketTest_Handshake();
		}

		preferences::set_use_rose_keyboard(false);

		game.register_server(server_rdpd, &game.rdpd_mgr());

		for (; ;) {
			game.loadscreen_manager().reset();
			const font::floating_label_context label_manager;
			cursor::set(cursor::NORMAL);

			int res;
			{
				gui2::thome dlg(game.rdpd_mgr());
				dlg.show();
				res = static_cast<gui2::thome::tresult>(dlg.get_retval());
			}

			if (res == gui2::thome::EXPLORER) {
				gui2::texplorer::tentry extra(null_str, null_str, null_str);
				if (game_config::os == os_windows) {
					extra = gui2::texplorer::tentry(game_config::path + "/data/gui/default/scene", _("gui/scene"), "misc/dir-res.png");
				} else if (game_config::os == os_android) {
					extra = gui2::texplorer::tentry("/sdcard", "/sdcard", "misc/dir-res.png");
				}

				gui2::texplorer dlg(game.rdpd_mgr(), null_str, extra, false);
				dlg.show();
				int res = dlg.get_retval();
				if (res != gui2::twindow::OK) {
					continue;
				}
			}

		}

	} catch (twml_exception& e) {
		e.show();

	} catch (CVideo::quit&) {
		//just means the game should quit
		SDL_Log("SDL_main, catched CVideo::quit\n");

	} catch (game_logic::formula_error& e) {
		gui2::show_error_message(e.what());
	} 

	return 0;
}

int main(int argc, char** argv)
{
	try {
		do_gameloop(argc, argv);
	} catch (twml_exception& e) {
		// this exception is generated when create instance.
		e.show();
	}

	return 0;
}