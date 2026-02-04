#pragma once
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <boost/asio/ip/udp.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

namespace udpsocket
{
static constexpr uint8_t v4v6Index = 12;

/** @class Channel
 *
 *  @brief Provides encapsulation for UDP socket operations like Read, Peek,
 *         Write, Remote peer's IP Address and Port.
 */
class Channel
{
  public:
    Channel() = delete;
    ~Channel() = default;
    Channel(const Channel& right) = delete;
    Channel& operator=(const Channel& right) = delete;
    Channel(Channel&&) = delete;
    Channel& operator=(Channel&&) = delete;

    /**
     * @brief Constructor
     *
     * Initialize the IPMI socket object with the socket descriptor
     *
     * @param [in] pointer to a boost::asio udp socket object
     *
     * @return None
     */
    explicit Channel(std::shared_ptr<boost::asio::ip::udp::socket> socket) :
        socket(socket)
    {}
    /**
     * @brief Check if ip address is ipv4 mapped ipv6
     *
     *  @param v6Addr : in6_addr obj
     *
     * @return true if ipv4 mapped ipv6 else return false
     */
    bool isIpv4InIpv6(const struct in6_addr& v6Addr) const
    {
        constexpr uint8_t prefix[v4v6Index] = {0, 0, 0, 0, 0,    0,
                                               0, 0, 0, 0, 0xff, 0xff};
        return 0 == std::memcmp(&v6Addr.s6_addr[0], &prefix[0], sizeof(prefix));
    }
    /**
     * @brief Fetch the IP address of the remote peer
     *
     *  @param remoteIpv4Addr : ipv4 address is assigned to it.
     *
     * Returns the IP address of the remote peer which is connected to this
     * socket
     *
     * @return IP address of the remote peer
     */
    std::string getRemoteAddress(uint32_t& remoteIpv4Addr) const
    {
        const char* retval = nullptr;
        if (sockAddrSize == sizeof(sockaddr_in))
        {
            char ipv4addr[INET_ADDRSTRLEN];
            const sockaddr_in* sa =
                reinterpret_cast<const sockaddr_in*>(&remoteSockAddr);
            remoteIpv4Addr = sa->sin_addr.s_addr;
            retval =
                inet_ntop(AF_INET, &(sa->sin_addr), ipv4addr, sizeof(ipv4addr));
        }
        else if (sockAddrSize == sizeof(sockaddr_in6))
        {
            char ipv6addr[INET6_ADDRSTRLEN];
            const sockaddr_in6* sa =
                reinterpret_cast<const sockaddr_in6*>(&remoteSockAddr);

            if (isIpv4InIpv6(sa->sin6_addr))
            {
                std::copy_n(&sa->sin6_addr.s6_addr[v4v6Index],
                            sizeof(remoteIpv4Addr),
                            reinterpret_cast<uint8_t*>(&remoteIpv4Addr));
            }
            retval = inet_ntop(AF_INET6, &(sa->sin6_addr), ipv6addr,
                               sizeof(ipv6addr));
        }

        if (retval)
        {
            return retval;
        }
        lg2::error("Error in inet_ntop: {ERROR}", "ERROR", strerror(errno));
        return std::string();
    }

    std::map<std::string, std::string>
        loadIpToMacMapping(const std::string& filename)
    {
        using namespace phosphor::logging;
        std::map<std::string, std::string> ipToMac;
        std::ifstream file(filename);
        std::string line, msg;

        if (!file.is_open())
        {
            msg = "Can not open file " + filename;
            log<level::INFO>(msg.c_str());
            return ipToMac;
        }

        while (getline(file, line))
        {
            std::istringstream iss(line);
            std::string ip, dummy, mac;
            iss >> ip >> dummy >> dummy >> mac;
            ipToMac[ip] = mac;
        }

        file.close();
        return ipToMac;
    }

    std::vector<uint8_t> getRemoteMac(std::string remoteIpv4Addr)
    {
        using namespace phosphor::logging;
        std::vector<uint8_t> retMacAddr(6, 0);
        const std::string arpFile = "/proc/net/arp";
        std::string ip, msg, mac, item;
        auto ipToMac = loadIpToMacMapping(arpFile);

        // remoteIpv4Addr will be like ::ffff:192.168.56.105
        size_t pos = remoteIpv4Addr.rfind(':');
        if (pos != std::string::npos)
        {
            ip = remoteIpv4Addr.substr(pos + 1);
        }

        if (ipToMac.find(ip) != ipToMac.end())
        {
            mac = ipToMac.at(ip);
        }
        else
        {
            /*Due to the restrictions of the subnet partition,
            it might not be possible to retrieve the corresponding IP's MAC
            address. */
            return retMacAddr;
        }

        std::stringstream ss(mac);
        retMacAddr.clear();
        while (getline(ss, item, ':'))
        {
            unsigned int value;
            std::stringstream converter(item);
            converter >> std::hex >> value;
            retMacAddr.push_back(static_cast<uint8_t>(value));
        }
        return retMacAddr;
    }

    /**
     * @brief Fetch the port number of the remote peer
     *
     * Returns the port number of the remote peer
     *
     * @return Port number
     *
     */
    uint16_t getPort() const
    {
        if (sockAddrSize == sizeof(sockaddr_in))
        {
            return ntohs(reinterpret_cast<const sockaddr_in*>(&remoteSockAddr)
                             ->sin_port);
        }
        if (sockAddrSize == sizeof(sockaddr_in6))
        {
            return ntohs(reinterpret_cast<const sockaddr_in6*>(&remoteSockAddr)
                             ->sin6_port);
        }
        return 0;
    }

    /**
     * @brief Read the incoming packet
     *
     * Reads the data available on the socket
     *
     * @return A tuple with return code and vector with the buffer
     *         In case of success, the vector is populated with the data
     *         available on the socket and return code is 0.
     *         In case of error, the return code is < 0 and vector is set
     *         to size 0.
     */
    std::tuple<int, std::vector<uint8_t>> read()
    {
        // cannot use the standard asio reading mechanism because it does not
        // provide a mechanism to reach down into the depths and use a msghdr
        std::vector<uint8_t> packet(socket->available());
        iovec iov = {packet.data(), packet.size()};
        char msgCtrl[1024];
        msghdr msg = {&remoteSockAddr, sizeof(remoteSockAddr), &iov, 1,
                      msgCtrl,         sizeof(msgCtrl),        0};

        ssize_t bytesReceived = recvmsg(socket->native_handle(), &msg, 0);
        // Read of the packet failed
        if (bytesReceived < 0)
        {
            // something bad happened; bail
            lg2::error("Error in recvmsg: {ERROR}", "ERROR",
                       strerror(-bytesReceived));
            return std::make_tuple(-errno, std::vector<uint8_t>());
        }
        // save the size of either ipv4 or i4v6 sockaddr
        sockAddrSize = msg.msg_namelen;

        // extract the destination address from the message
        cmsghdr* cmsg;
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != 0;
             cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
            {
                // save local address from the pktinfo4
                pktinfo4 = *reinterpret_cast<in_pktinfo*>(CMSG_DATA(cmsg));
            }
            if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                cmsg->cmsg_type == IPV6_PKTINFO)
            {
                // save local address from the pktinfo6
                pktinfo6 = *reinterpret_cast<in6_pktinfo*>(CMSG_DATA(cmsg));
            }
        }
        return std::make_tuple(0, packet);
    }

    /**
     *  @brief Write the outgoing packet
     *
     *  Writes the data in the vector to the socket
     *
     *  @param [in] inBuffer
     *      The vector would be the buffer of data to write to the socket.
     *
     *  @return In case of success the return code is the number of bytes
     *          written and return code is < 0 in case of failure.
     */
    int write(const std::vector<uint8_t>& inBuffer)
    {
        // in order to make sure packets go back out from the same
        // IP address they came in on, sendmsg must be used instead
        // of the boost::asio::ip::send or sendto
        iovec iov = {const_cast<uint8_t*>(inBuffer.data()), inBuffer.size()};
        char msgCtrl[1024];
        msghdr msg = {&remoteSockAddr, sockAddrSize,    &iov, 1,
                      msgCtrl,         sizeof(msgCtrl), 0};
        int cmsg_space = 0;
        cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        if (pktinfo6)
        {
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
            *reinterpret_cast<in6_pktinfo*>(CMSG_DATA(cmsg)) = *pktinfo6;
            cmsg_space += CMSG_SPACE(sizeof(in6_pktinfo));
        }
        else if (pktinfo4)
        {
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
            *reinterpret_cast<in_pktinfo*>(CMSG_DATA(cmsg)) = *pktinfo4;
            cmsg_space += CMSG_SPACE(sizeof(in_pktinfo));
        }
        msg.msg_controllen = cmsg_space;
        int ret = sendmsg(socket->native_handle(), &msg, 0);
        if (ret < 0)
        {
            lg2::error("Error in sendmsg: {ERROR}", "ERROR", strerror(-ret));
        }
        return ret;
    }

    /**
     * @brief Returns file descriptor for the socket
     */
    auto getHandle(void) const
    {
        return socket->native_handle();
    }

  private:
    std::shared_ptr<boost::asio::ip::udp::socket> socket;
    sockaddr_storage remoteSockAddr;
    socklen_t sockAddrSize;
    std::optional<in_pktinfo> pktinfo4;
    std::optional<in6_pktinfo> pktinfo6;
};

} // namespace udpsocket
