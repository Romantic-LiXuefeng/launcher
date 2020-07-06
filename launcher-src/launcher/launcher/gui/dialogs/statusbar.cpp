#define GETTEXT_DOMAIN "launcher-lib"

#include "gui/dialogs/statusbar.hpp"

#include "gui/widgets/label.hpp"
#include "gui/widgets/image.hpp"
#include "gui/widgets/window.hpp"
#include "gettext.hpp"
#include "formula_string_utils.hpp"
#include "game_config.hpp"
#include "filesystem.hpp"
#include "SDL_power.h"
#include "version.hpp"

#include <net/server/rdp_connection.h>

namespace gui2 {

tstatusbar::tstatusbar(net::trdpd_manager& rdpd_mgr)
	: rdpd_mgr_(rdpd_mgr)
	, window_priv_(nullptr)
	, statusbar_widget_(nullptr)
	, client_widget_(nullptr)
	, client_ip_widget_(nullptr)
	, time_widget_(nullptr)
{
}

void tstatusbar::pre_show(twindow& window, tgrid& statusbar_widget)
{
	VALIDATE(!window_priv_ && !statusbar_widget_, null_str);
	window_priv_ = &window;
	statusbar_widget_ = &statusbar_widget;

	client_widget_ = find_widget<timage>(&window, "client", false, true);
	client_ip_widget_ = find_widget<tlabel>(&window, "client_ip", false, true);
	time_widget_ = find_widget<tlabel>(&window, "time", false, true);

	refresh_statusbar_grid();
}

void tstatusbar::refresh_statusbar_grid()
{
	std::string client_icon = "misc/no-mobile.png";
	std::string client_ip;
	if (rdpd_mgr_.started()) {
		net::RdpServer& server = rdpd_mgr_.rdp_server();
		if (server.normal_connection_count() != 0) {
			client_icon = "misc/mobile.png";
			net::RdpConnection* connection = server.FindFirstNormalConnection();
			VALIDATE(connection != nullptr, null_str);
			const net::IPEndPoint& peer = connection->peer_ip();
			client_ip = peer.ToStringWithoutPort();
		}
	}
	client_widget_->set_label(client_icon);
	client_ip_widget_->set_label(client_ip);

	std::stringstream ss;
	ss << rdpd_mgr_.url() << " ";
	ss << format_time_hm(time(nullptr));
	time_widget_->set_label(ss.str());
}

} // namespace gui2

