#pragma once

#include <boost/asio/io_context.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <cstddef>
#include <memory>

// Select call timeout is set arbitrarily set to 30 sec
static constexpr size_t SELECT_CALL_TIMEOUT = 30;
static const auto IPMI_STD_PORT = 623;

extern sd_bus* bus;

std::shared_ptr<sdbusplus::asio::connection> getSdBus();
std::shared_ptr<boost::asio::io_context> getIo();
std::shared_ptr<sdbusplus::asio::object_server> getObjServer();
