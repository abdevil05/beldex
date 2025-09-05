#pragma once

#include <boost/optional/optional.hpp>
#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <zmq.h>
#include <nlohmann/json.hpp>

#include "oxenmq/oxenmq.h"
#include "oxenmq/connections.h"
#include "epee/span.h"
#include "epee/misc_log_ex.h"

#include "rpc/daemon_pub.h"

using json = nlohmann::json;
using namespace oxenmq;

using LMQ_ptr = std::shared_ptr<oxenmq::OxenMQ>;

namespace lws
{
 namespace rpc
 {
 namespace detail
 {
    struct close
    {
      void operator()(void* ptr) const noexcept
      {
        if (ptr)
          zmq_close(ptr);
      }
    };
    using socket = std::unique_ptr<void, close>;

    struct context;
 }//detail
 
  class context
  {
    std::shared_ptr<detail::context> ctx;

    explicit context(std::shared_ptr<detail::context> ctx)
      : ctx(std::move(ctx))
    {}

  public:
    /*! Use `daemon_addr` for call child client objects.

      \throw std::bad_alloc if internal `shared_ptr` allocation failed.
      \throw std::system_error if any ZMQ errors occur.

      \note All errors are exceptions; no recovery can occur.

      \param daemon_addr Location of ZMQ enabled `monerod` RPC.
      \param rates_interval Frequency to retrieve exchange rates. Set value to
        `<= 0` to disable exchange rate retrieval.
    */
    static context make(std::string daemon_addr, std::string sub_addr, std::chrono::minutes rates_interval);

    context(context&&) = default;
    context(context const&) = delete;

    //! Calls `raise_abort_process()`. Clients can safely destruct later.
    ~context() noexcept;

    context& operator=(context&&) = default;
    context& operator=(context const&) = delete;

    // Do not create clone method, only one of these should exist right now.

    //! \return The full address of the monerod ZMQ daemon.
    std::string const& daemon_address() const;

    //! \return Client connection. Thread-safe.
    // expect<client> connect() const noexcept
    // {
    //   return client::make(ctx);
    // }

    /*!
      All block `client::send`, `client::receive`, and `client::wait` calls
      originating from `this` object AND whose `watch_scan_signal` method was
      invoked, will immediately return with `lws::error::kSignlAbortScan`. This
      is NOT signal-safe NOR signal-safe NOR thread-safe.
    */
    // expect<void> raise_abort_scan() noexcept;

    /*!
      All blocked `client::send`, `client::receive`, and `client::wait` calls
      originating from `this` object will immediately return with
      `lws::error::kSignalAbortProcess`. This call is NOT signal-safe NOR
      thread-safe.
    */
    // expect<void> raise_abort_process() noexcept;

    /*!
      Retrieve exchange rates, if enabled and past cache interval. Not
      thread-safe (this can be invoked from one thread only, but this is
      thread-safe with `client::get_rates()`). All clients will see new rates
      immediately.

      \return Rates iff they were updated.
    */
    // expect<boost::optional<lws::rates>> retrieve_rates();
  };

  struct Connection{
    oxenmq::ConnectionID c;
    LMQ_ptr m_LMQ;
    bool daemon_connected = false;
    
  };

  Connection connect_daemon();


 }//rpc
}//lws