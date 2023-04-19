#pragma once

#include <string>
#include <vector>

#include "net/dns_manager.h"
#include "net/socket_manager.h"
#include "vpn/utils.h"

namespace ag {

/**
 * Network manager of VPN client operations
 */
struct VpnNetworkManager {
    DnsManager *dns;       // DNS manager (optional: needed only for the SOCKS listener)
    SocketManager *socket; // Socket manager
};

/**
 * Get a network manager
 */
VpnNetworkManager *vpn_network_manager_get();

/**
 * Destroy a network manager
 */
void vpn_network_manager_destroy(VpnNetworkManager *m);

/**
 * Update system DNS servers
 */
bool vpn_network_manager_update_system_dns(SystemDnsServers servers);

/**
 * Notify that a domain is about to be queried by an application
 * @param domain the domain name
 * @param timeout_ms the amount of time after which the record will be forgotten (negative means default)
 */
extern "C" WIN_EXPORT void vpn_network_manager_notify_app_request_domain(const char *domain, int timeout_ms);

/**
 * Check whether a domain belongs to queries from an application
 */
bool vpn_network_manager_check_app_request_domain(const char *domain);

/**
 * Set the outbound interface that will be used for outgoing connections.
 * [Windows] The currently active interface may be found with `vpn_win_detect_active_if()`.
 * @param idx if >0, the library sets it as is
 *            if =0, the library uses the default one
 */
extern "C" WIN_EXPORT void vpn_network_manager_set_outbound_interface(uint32_t idx);

/**
 * Get the outbound interface for outgoing connections
 */
uint32_t vpn_network_manager_get_outbound_interface();

} // namespace ag
