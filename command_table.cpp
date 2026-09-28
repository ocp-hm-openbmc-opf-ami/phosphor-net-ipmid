#include "command_table.hpp"

#include "main.hpp"
#include "message_handler.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"

#include <ipmid/types.hpp>
#include <main.hpp>
#include <phosphor-logging/lg2.hpp>
#include <user_channel/user_layer.hpp>

#include <iomanip>
#ifndef ALLOW_ROOT_LOGIN
#include <shadow.h>
#endif

namespace command
{
#ifndef ALLOW_ROOT_LOGIN
bool CheckExpiredUser(std::string userName)
{
    struct spwd spwd{};
    struct spwd* spwdPtr = nullptr;
    auto buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buflen == -1)
    {
        // Use a default size if there is no hard limit suggested by sysconf()
        buflen = 1024;
    }
    std::vector<char> buffer(buflen);
    auto status =
        getspnam_r(userName.c_str(), &spwd, buffer.data(), buflen, &spwdPtr);
    // On success, getspnam_r() returns zero, and sets *spwdPtr to spwd.
    // If no matching password record was found, these functions return 0
    // and store NULL in *spwdPtr
    if ((status == 0) && (&spwd == spwdPtr))
    {
        // Determine password validity per "chage" docs, where:
        //   spwd.sp_lstchg == 0 means password is expired, and
        //   spwd.sp_max == -1 means the password does not expire.
        constexpr long secondsPerDay = 60 * 60 * 24;
        long today = static_cast<long>(time(NULL)) / secondsPerDay;
        if ((spwd.sp_lstchg == 0) ||
            ((spwd.sp_max != -1) && ((spwd.sp_max + spwd.sp_lstchg) < today)))
        {
            return true;
        }
    }
    else
    {
        // User entry is missing in /etc/shadow, indicating no SHA password.
        // Treat this as new user without password entry in /etc/shadow
        // TODO: Add property to indicate user password was not set yet
        // https://github.com/openbmc/phosphor-user-manager/issues/8
        return false;
    }

    return false;
}
#endif

void Table::registerCommand(CommandID inCommand, std::unique_ptr<Entry>&& entry)
{
    auto& command = commandTable[inCommand.command];

    if (command)
    {
        if (debug)
        {
            lg2::debug("Already Registered: {COMMAND}", "COMMAND",
                       inCommand.command);
        }
        return;
    }

    command = std::move(entry);
}

void Table::executeCommand(uint32_t inCommand,
                           std::vector<uint8_t>& commandData,
                           std::shared_ptr<message::Handler> handler)
{
    using namespace std::chrono_literals;
#ifndef ALLOW_ROOT_LOGIN
    // If the default user's password is expired, allow only the commands needed
    // to set a new password and block everything else until it is changed.
    std::vector<int> cmds = {71 /*0x47*/, 56 /*0x38*/, 1 /*0x01*/, 62 /*0x3e*/,
                             0 /*0x00*/};
    std::vector<int> netFns = {6 /*0x06*/, 44 /*0x2c*/};
    size_t CmdCounter = 0, NetfnCounter = 0;
    bool matchFound = false;
#endif

    auto iterator = commandTable.find(inCommand);

    if (iterator == commandTable.end())
    {
        CommandID command(inCommand);

        // Do not forward any session zero commands to ipmid
        if (handler->sessionID == session::sessionZero)
        {
            lg2::info(
                "Table: refuse to forward session-zero command: lun: {LUN}, netFn: {NETFN}, command: {COMMAND}",
                "LUN", command.lun(), "NETFN", command.netFn(), "COMMAND",
                command.cmd());
            return;
        }
        std::shared_ptr<session::Session> session =
            session::Manager::get().getSession(handler->sessionID);

        // Ignore messages that are not part of an active session
        auto state = static_cast<session::State>(session->state());
        if (state != session::State::active)
        {
            return;
        }

        auto bus = getSdBus();
        // forward the request onto the main ipmi queue
        using IpmiDbusRspType = std::tuple<uint8_t, uint8_t, uint8_t, uint8_t,
                                           std::vector<uint8_t>>;
        uint8_t lun = command.lun();
        uint8_t netFn = command.netFn();
        uint8_t cmd = command.cmd();

        std::map<std::string, ipmi::Value> options = {
            {"userId", ipmi::Value(static_cast<int>(
                           ipmi::ipmiUserGetUserId(session->userName)))},
            {"privilege",
             ipmi::Value(static_cast<int>(session->currentPrivilege()))},
            {"currentSessionId",
             ipmi::Value(static_cast<uint32_t>(session->getBMCSessionID()))},
        };
#ifndef ALLOW_ROOT_LOGIN
        if ((session->userName == "admin") &&
            (CheckExpiredUser(session->userName) == true))
        {
            for (CmdCounter = 0; CmdCounter < cmds.size(); ++CmdCounter)
            {
                if (cmd == cmds[CmdCounter])
                {
                    for (NetfnCounter = 0; NetfnCounter < netFns.size();
                         ++NetfnCounter)
                    {
                        if (netFn == netFns[NetfnCounter])
                        {
                            matchFound = true;
                            break;
                        }
                    }
                }
                if (matchFound)
                {
                    break;
                }
            }

            if (matchFound == false)
            {
                std::vector<uint8_t> payload;
                payload.push_back(ipmi::ccNeedToChangeUserPassword);
                handler->outPayload = std::move(payload);
                return;
            }
        }
#endif
        bus->async_method_call(
            [handler](const boost::system::error_code& ec,
                      const IpmiDbusRspType& response) {
                if (!ec)
                {
                    const uint8_t& cc = std::get<3>(response);
                    const std::vector<uint8_t>& responseData =
                        std::get<4>(response);
                    std::vector<uint8_t> payload;
                    payload.reserve(1 + responseData.size());
                    payload.push_back(cc);
                    payload.insert(payload.end(), responseData.begin(),
                                   responseData.end());
                    handler->outPayload = std::move(payload);
                }
                else
                {
                    std::vector<uint8_t> payload;
                    payload.push_back(IPMI_CC_UNSPECIFIED_ERROR);
                    handler->outPayload = std::move(payload);
                }
            },
            "xyz.openbmc_project.Ipmi.Host", "/xyz/openbmc_project/Ipmi",
            "xyz.openbmc_project.Ipmi.Server", "execute", netFn, lun, cmd,
            commandData, options);
    }
    else
    {
        auto start = std::chrono::steady_clock::now();

        // Ignore messages that are not part of an active/pre-active session
        if (handler->sessionID != session::sessionZero)
        {
            std::shared_ptr<session::Session> session =
                session::Manager::get().getSession(handler->sessionID);
            auto state = static_cast<session::State>(session->state());
            if ((state != session::State::setupInProgress) &&
                (state != session::State::active))
            {
                return;
            }
        }

        handler->outPayload =
            iterator->second->executeCommand(commandData, handler);

        auto end = std::chrono::steady_clock::now();

        std::chrono::duration<size_t> elapsedSeconds =
            std::chrono::duration_cast<std::chrono::seconds>(end - start);

        // If command time execution time exceeds 2 seconds, log a time
        // exceeded message
        if (elapsedSeconds > 2s)
        {
            lg2::error("IPMI command timed out: {DELAY}", "DELAY",
                       elapsedSeconds.count());
        }
    }
}

std::vector<uint8_t> NetIpmidEntry::executeCommand(
    std::vector<uint8_t>& commandData,
    std::shared_ptr<message::Handler> handler)
{
    std::vector<uint8_t> errResponse;

    // Check if the command qualifies to be run prior to establishing a session
    if (!sessionless && (handler->sessionID == session::sessionZero))
    {
        errResponse.resize(1);
        errResponse[0] = IPMI_CC_INSUFFICIENT_PRIVILEGE;
        lg2::info(
            "Table: Insufficient privilege for command: lun: {LUN}, netFn: {NETFN}, command: {COMMAND}",
            "LUN", command.lun(), "NETFN", command.netFn(), "COMMAND",
            command.cmd());
        return errResponse;
    }

    return functor(commandData, handler);
}

} // namespace command
