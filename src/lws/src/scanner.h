#pragma once

#include <atomic>
#include <boost/optional/optional.hpp>
#include <cstdint>
#include <string>
#include "db/storage.h"
#include "db/data.h"
#include "rpc/client.h"

namespace lws
{
    class scanner
    {
        static std::atomic<bool> running;
        scanner() = delete;

    public:

        //! Use `client` to sync blockchain data, and \return client if successful.
        static void sync(db::storage disk,std::string daemon_rpc);
        // std::string wallet2::get_subaddress_as_str(const cryptonote::subaddress_index& index) const
        // {
        // cryptonote::account_public_address address = get_subaddress(index);
        // return cryptonote::get_account_address_as_str(m_nettype, !index.is_zero(), address);
        // }
        // std::string get_address_as_str() const { return get_subaddress_as_str({0, 0}); }

        //! Poll daemon until `stop()` is called, using `thread_count` threads.
        static void run(db::storage disk, std::string daemon_rpc,std::size_t thread_count);

        //! \return True if `stop()` has never been called.
        static bool is_running() noexcept { return running; }

        //! Stops all scanner instances globally.
        static void stop() noexcept { std::cout << "STOP_ACTION called" << std::endl;running = false; }
    };

} //lws