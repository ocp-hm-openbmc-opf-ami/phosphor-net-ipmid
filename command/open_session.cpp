#include "open_session.hpp"

#include "comm_module.hpp"
#include "endian.hpp"
#include "sessions_manager.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>

#include <fstream>
#include <mutex>

namespace command
{

static constexpr const char* cipherListFile =
    "/usr/share/ipmi-providers/cipher_list.json";

static constexpr int invalidCipherId = -1;

static nlohmann::json cachedCipherList;
static bool loaded = false;
static std::once_flag cipherListLoadFlag;

static bool loadOnce()
{
    std::ifstream jsonFile(cipherListFile);
    if (!jsonFile.is_open())
    {
        lg2::error("Cipher list file not found");
        return false;
    }

    cachedCipherList = nlohmann::json::parse(jsonFile, nullptr, false);
    if (cachedCipherList.is_discarded())
    {
        lg2::error("Failed to parse cipher list JSON");
        return false;
    }

    return true;
}

/** @brief Get cipher suite ID for the requested algorithm combination from
 *         cipher_list.json.
 *
 *  @param[in] authAlgo  - requested authentication algorithm
 *  @param[in] intAlgo   - requested integrity algorithm
 *  @param[in] confAlgo  - requested confidentiality algorithm
 *
 *  @return cipher suite ID if combination is configured, invalidCipherId
 *          otherwise
 */
static int getCipherIdFromConfig(uint8_t authAlgo, uint8_t intAlgo,
                                 uint8_t confAlgo)
{
    if (!loaded)
    {
        std::call_once(cipherListLoadFlag, [&]() { loaded = loadOnce(); });
        if (!loaded)
        {
            lg2::error("Cipher list unavailable, rejecting session");
            return invalidCipherId;
        }
    }

    for (const auto& record : cachedCipherList)
    {
        if (record.value("authentication", 0) == authAlgo &&
            record.value("integrity", 0) == intAlgo &&
            record.value("confidentiality", 0) == confAlgo)
        {
            return record.value("cipher", invalidCipherId);
        }
    }
    return invalidCipherId;
}

std::vector<uint8_t> openSession(
    const std::vector<uint8_t>& inPayload,
    std::shared_ptr<message::Handler>& /* handler */)
{
    auto request =
        reinterpret_cast<const OpenSessionRequest*>(inPayload.data());
    if (inPayload.size() != sizeof(*request))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }

    std::vector<uint8_t> outPayload(sizeof(OpenSessionResponse));
    auto response = reinterpret_cast<OpenSessionResponse*>(outPayload.data());

    // Per the IPMI Spec, messageTag and remoteConsoleSessionID are always
    // returned
    response->messageTag = request->messageTag;
    response->remoteConsoleSessionID = request->remoteConsoleSessionID;

    // Check for valid Authentication Algorithms
    if (!cipher::rakp_auth::Interface::isAlgorithmSupported(
            static_cast<cipher::rakp_auth::Algorithms>(request->authAlgo)))
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_AUTH_ALGO);
        return outPayload;
    }

    // Check for valid Integrity Algorithms
    if (!cipher::integrity::Interface::isAlgorithmSupported(
            static_cast<cipher::integrity::Algorithms>(request->intAlgo)))
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_INTEGRITY_ALGO);
        return outPayload;
    }

    int resolvedCipherId = getCipherIdFromConfig(request->authAlgo,
                                                 request->intAlgo,
                                                 request->confAlgo);
    if (resolvedCipherId == invalidCipherId)
    {
        lg2::error(
            "Cipher suite combination not configured, rejecting session");
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::NO_CIPHER_SUITE_MATCH);
        return outPayload;
    }

    uint8_t cipherPrivLimit = 0;
    uint8_t cipherId = static_cast<uint8_t>(resolvedCipherId);

    uint8_t chNum = static_cast<uint8_t>(getInterfaceIndex());
    cipherPrivLimit =
        static_cast<uint8_t>(getCipherPrivilegeLimit(chNum, cipherId));

    if (cipherPrivLimit == 0)
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INSUFFICIENT_RESOURCES_ROLE);
        return outPayload;
    }

    session::Privilege priv;

    // 0h in the requested maximum privilege role field indicates highest level
    // matching proposed algorithms. The maximum privilege level the session
    // can take is set to Administrator level. In the RAKP12 command sequence
    // the session maximum privilege role is set again based on the user's
    // permitted privilege level.
    if (!request->maxPrivLevel)
    {
        priv = static_cast<session::Privilege>(cipherPrivLimit);
    }
    else
    {
        if (request->maxPrivLevel <= cipherPrivLimit)
        {
            priv = static_cast<session::Privilege>(request->maxPrivLevel);
        }
        else
        {
            response->status_code =
                static_cast<uint8_t>(RAKP_ReturnCode::UNAUTH_ROLE_PRIV);
            return outPayload;
        }
    }

    // Check for valid Confidentiality Algorithms
    if (!cipher::crypt::Interface::isAlgorithmSupported(
            static_cast<cipher::crypt::Algorithms>(request->confAlgo)))
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_CONF_ALGO);
        return outPayload;
    }

    std::shared_ptr<session::Session> session;
    try
    {
        // Start an IPMI session
        session = session::Manager::get().startSession(
            endian::from_ipmi<>(request->remoteConsoleSessionID), priv,
            static_cast<cipher::rakp_auth::Algorithms>(request->authAlgo),
            static_cast<cipher::integrity::Algorithms>(request->intAlgo),
            static_cast<cipher::crypt::Algorithms>(request->confAlgo));
    }
    catch (const std::exception& e)
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INSUFFICIENT_RESOURCE);
        lg2::error("openSession : Problem opening a session: {ERROR}", "ERROR",
                   e);
        return outPayload;
    }

    response->status_code = static_cast<uint8_t>(RAKP_ReturnCode::NO_ERROR);
    response->maxPrivLevel = static_cast<uint8_t>(session->reqMaxPrivLevel);
    response->managedSystemSessionID =
        endian::to_ipmi<>(session->getBMCSessionID());

    response->authPayload = request->authPayload;
    response->authPayloadLen = request->authPayloadLen;
    response->authAlgo = request->authAlgo;

    response->intPayload = request->intPayload;
    response->intPayloadLen = request->intPayloadLen;
    response->intAlgo = request->intAlgo;

    response->confPayload = request->confPayload;
    response->confPayloadLen = request->confPayloadLen;
    response->confAlgo = request->confAlgo;

    session->updateLastTransactionTime();

    // Session state is Setup in progress
    session->state(static_cast<uint8_t>(session::State::setupInProgress));
    return outPayload;
}

} // namespace command
