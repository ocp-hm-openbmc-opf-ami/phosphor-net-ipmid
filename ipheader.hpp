#include "main.hpp"
#include <boost/asio.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <nlohmann/json.hpp>
#include <fstream>

namespace ipheader
{

#define DEFTIMETOLIVE 64
#define DEFFLAG 64
#define DEFTYPEOFSERVICE 16
#define DEFTRAFFICCLASS 0
#define DEFHOPLIMIT 64


struct IPHeader
{

public:

    uint8_t timeToLive;
    uint8_t flag;
    uint8_t typeOfService;
    uint8_t trafficClass;
    uint8_t hopLimit;

    IPHeader(uint8_t timetoLive, uint8_t flags, uint8_t typeofService, uint8_t trafficclass, 
	     uint8_t hoplimit): timeToLive(timetoLive), flag(flags), typeOfService(typeofService),
	     trafficClass(trafficclass), hopLimit(hoplimit){
    }

    /**
     * @brief Get a reference to the IPHeader
     *
     * @return IPHeader reference
     */
    static IPHeader& get()
    {
        static std::shared_ptr<IPHeader> ptr = nullptr;
        if (!ptr)
        {
            ptr = std::make_shared<IPHeader>(DEFTIMETOLIVE,DEFFLAG,DEFTYPEOFSERVICE,DEFTRAFFICCLASS,DEFHOPLIMIT);
        }
        return *ptr;
    }

   /** @brief reads the ip header info from file.
     *  @param[in] confFile - configuration filename
     *  @returns json file data
     */
    nlohmann::json readJsonFile(const std::string& confFile)
    {
        std::ifstream jsonFile(confFile);
        if (!jsonFile.good())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>("JSON file not found",
				   phosphor::logging::entry("FILE=%s", confFile.c_str()));
	   return nullptr;
        }

        nlohmann::json data = nullptr;
        try
        {
            data = nlohmann::json::parse(jsonFile, nullptr, false);
        }
        catch (nlohmann::json::parse_error& e)
        {
            throw std::runtime_error("Corrupted lan config file");
        }

        return data;
    }

    /** @brief writes the ip header info to file.
     *  @param[in] confFile - configuration filename
     *  @param[in] jsonData - json data to write
     *  @returns success or failure
     */
    int writeJsonFile(const std::string& confFile, const nlohmann::json& jsonData)
    {
        std::ofstream jsonFile(confFile);
        if (!jsonFile.good())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>("JSON file open failed",
				   phosphor::logging::entry("FILE=%s", confFile.c_str()));
            return -1;
        }

        // Write JSON to file
        jsonFile << jsonData;

        jsonFile.flush();
        return 0;
    }

    std::shared_ptr<sdbusplus::asio::dbus_interface> ipHeadIntf = nullptr;

    /** @brief sets the ipv4 header parameters on socket.
     *  @param[in] timetoLive - Time to Live field in IP Header
     *  @param[in] flags - Flags field in IP Header
     *  @param[in] typeofService - Type Of Service and Precedence
     *  @returns success or failure
     */
    int SetIPv4Header( uint8_t timetoLive, uint8_t flags, uint8_t typeofService)
    {
        if(timetoLive < 1)
        {
            throw std::runtime_error("Invalid argument value TimeToLive");
        }
        if(flags & 0x9F)
        {
            throw std::runtime_error("Invalid argument value Flags");
        }
        if(typeofService & 0x01)
        {
            throw std::runtime_error("Invalid argument value TypeOfService");
        }

	timeToLive = timetoLive;
	flag=flags;
	typeOfService=typeofService;
	updateProperty(ipHeadIntf,timeToLive,"TimeToLive");
	updateProperty(ipHeadIntf,flag,"Flags");
	updateProperty(ipHeadIntf,typeOfService,"TypeOfService");

	auto& obj = eventloop::EventLoop::get();

	if(obj.updateSocket("IPv4") == -1)
	{
            throw std::runtime_error("SetIPv4Header failed");
	}

	nlohmann::json jsonData = readJsonFile(configFilename);
        jsonData["TimeToLive"] = timeToLive;
        jsonData["Flags"] = flag;
        jsonData["TypeOfService"] = typeOfService;

	writeJsonFile(configFilename, jsonData);

	return 0;
    }

    /** @brief sets the ipv6 header parameters on socket.
     *  @param[in] TrafficClass - Traffic Class field in IPv6 Header
     *  @param[in] HopLimit - Hop Limit field in IPv6 Header
     *  @returns success or failure
     */
    int SetIPv6Header( uint8_t TrafficClass, uint8_t HopLimit)
    {
        if(TrafficClass & 0xC0)
        {
            throw std::runtime_error("Invalid argument value TrafficClass");
        }
	trafficClass = TrafficClass;
	hopLimit=HopLimit;

	updateProperty(ipHeadIntf,trafficClass,"TrafficClass");
	updateProperty(ipHeadIntf,hopLimit,"HopLimit");

	auto& obj = eventloop::EventLoop::get();

 	if(obj.updateSocket("IPv6") == -1)
	{
            throw std::runtime_error("SetIPv6Header failed");
	}

	nlohmann::json jsonData = readJsonFile(configFilename);
        jsonData["TrafficClass"] = trafficClass;
        jsonData["HopLimit"] = hopLimit;

	writeJsonFile(configFilename, jsonData);

	return 0;
    }

    void IPHeaderInit(std::string iface){

        auto objPath = std::string(session::sessionManagerRootPath) + "/" + iface + "/0";
	const char* ipHeadDbusIntf = "xyz.openbmc_project.Ipmi.IPHeader";

	configFilename = "/var/lib/ipmi/lancfg_" + iface + ".json";

        ipHeadIntf = std::make_shared<sdbusplus::asio::dbus_interface>(getSdBus(),objPath,ipHeadDbusIntf);

        ipHeadIntf->register_method("SetIPv4Header", [this]
                    (uint8_t timetolive, uint8_t flags, uint8_t typeofservice){
                        return this->SetIPv4Header(timetolive, flags, typeofservice);
                    });

        ipHeadIntf->register_property("TimeToLive", this->timeToLive);
        ipHeadIntf->register_property("Flags", this->flag);
        ipHeadIntf->register_property("TypeOfService", this->typeOfService);

        ipHeadIntf->register_method("SetIPv6Header", [this]
                    (uint8_t trafficclass, uint8_t hoplimit){
                        return this->SetIPv6Header(trafficclass, hoplimit);
                    });

        ipHeadIntf->register_property("TrafficClass", this->trafficClass);
        ipHeadIntf->register_property("HopLimit", this->hopLimit);

        ipHeadIntf->initialize();

	nlohmann::json jsonData = readJsonFile(configFilename);
	if (jsonData != nullptr)
	{
	    timeToLive = jsonData["TimeToLive"];
	    flag = jsonData["Flags"];
	    typeOfService = jsonData["TypeOfService"];

	    trafficClass = jsonData["TrafficClass"];
	    hopLimit = jsonData["HopLimit"];
	    updateProperty(ipHeadIntf,timeToLive,"TimeToLive");
	    updateProperty(ipHeadIntf,flag,"Flags");
	    updateProperty(ipHeadIntf,typeOfService,"TypeOfService");
	    updateProperty(ipHeadIntf,trafficClass,"TrafficClass");
	    updateProperty(ipHeadIntf,hopLimit,"HopLimit");
	}
	else
	{
	    jsonData["TimeToLive"] = timeToLive;
	    jsonData["Flags"] = flag;
	    jsonData["TypeOfService"] = typeOfService;
	    jsonData["TrafficClass"] = trafficClass;
	    jsonData["HopLimit"] = hopLimit;
	}

	writeJsonFile(configFilename, jsonData);

	auto& obj = eventloop::EventLoop::get();
	if(obj.updateSocket("IPv4") == -1)
	{
            phosphor::logging::log<phosphor::logging::level::ERR>("SetIPv4Header Failed");
	}

	if(obj.updateSocket("IPv6") == -1)
	{
            phosphor::logging::log<phosphor::logging::level::ERR>("SetIPv6Header Failed");
	}

    }

   private:

    std::string configFilename;

    void updateProperty(std::shared_ptr<sdbusplus::asio::dbus_interface>& interface,
                        uint8_t &value, const char* PropertyName)
    {
	if (interface && !(interface->set_property(PropertyName,value)))
	{
            phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("Error setting property " + std::string(PropertyName)).c_str(),
                    phosphor::logging::entry("VALUE=%l", value));
      }
    }
};

} //namespace ipheader
