#define GETTEXT_DOMAIN "launcher-lib"

#include "gui/dialogs/home.hpp"

#include "gui/widgets/label.hpp"
#include "gui/widgets/button.hpp"
#include "gui/widgets/window.hpp"
#include "gui/dialogs/menu.hpp"
#include "gettext.hpp"
#include "formula_string_utils.hpp"
#include "filesystem.hpp"
#include "version.hpp"
#include "base_instance.hpp"

#include "game_config.hpp"

#include <boost/bind.hpp>

namespace gui2 {

REGISTER_DIALOG(launcher, home)

thome::thome(net::trdpd_manager& rdpd_mgr)
	: tstatusbar(rdpd_mgr)
	, start_ticks_(SDL_GetTicks())
{
	set_timer_interval(1000);
}

void thome::pre_show()
{
	window_->set_escape_disabled(true);
	window_->set_label("misc/white-background.png");

	tstatusbar::pre_show(*window_, find_widget<tgrid>(window_, "statusbar_grid", false));

	std::stringstream ss;
	utils::string_map symbols;

	symbols["explorer"] = _("icon^Explorer");
	ss.str("");
	ss << vgettext2("launcher user remark, $explorer", symbols);
	ss << "\n";
	ss << "V" << game_config::version.str(true);
	ss << "     libkosapi: V" << game_config::kosapi_ver.str(true);
	find_widget<tlabel>(window_, "version", false).set_label(ss.str());

	tbutton* button = find_widget<tbutton>(window_, "explorer", false, true);
	connect_signal_mouse_left_click(
			  *button
			, boost::bind(
			&thome::click_explorer
			, this));

	// suppress_threshold
	button = find_widget<tbutton>(window_, "suppress_threshold", false, true);
	connect_signal_mouse_left_click(
			*button
		, boost::bind(
			&thome::click_suppress_threshold
			, this, boost::ref(*button)));
	button->set_label(game_config::suppress_thresholds.find(preferences::suppressthreshold())->second);
}

void thome::post_show()
{
}

void thome::click_explorer()
{
	window_->set_retval(EXPLORER);

	// SDL_UpdateApp("com.leagor.studio");
}

void thome::click_aismart()
{
/*
	// SDL_UpdateApp("com.leagor.aismart");
*/
}

void thome::click_suppress_threshold(tbutton& widget)
{
	std::vector<gui2::tmenu::titem> items;
	int initial_sel = nposm;

	for (std::map<int, std::string>::const_iterator it = game_config::suppress_thresholds.begin(); it != game_config::suppress_thresholds.end(); ++ it) {
		const int t = it->first;
		items.push_back(gui2::tmenu::titem(it->second, t));
		if (t == preferences::suppressthreshold()) {
			initial_sel = t;
		}
	}
	
	gui2::tmenu dlg(items, initial_sel);
	dlg.show(widget.get_x(), widget.get_y() + widget.get_height() + 16 * twidget::hdpi_scale);
	if (dlg.get_retval() != gui2::twindow::OK) {
		return;
	}

	const int t = dlg.selected_val();
	preferences::set_suppressthreshold(t);

	widget.set_label(game_config::suppress_thresholds.find(t)->second);
}

void thome::app_timer_handler(uint32_t now)
{
	refresh_statusbar_grid();
}

} // namespace gui2

