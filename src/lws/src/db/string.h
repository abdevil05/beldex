#pragma once

#include <boost/utility/string_ref.hpp>
#include <string>

#include "common/expect.h"
#include "db/fwd.h"

namespace lws
{
namespace  db
{
  //! Callable for converting `account_address` to/from monero base58 public address.
  struct address_string_
  {
    /*!
      \return `address` as a monero base58 public address, using
        `lws::config::network` for the tag.
    */
    std::string operator()(account_address const& address) const;
    /*!
      \return `address`, as base58 public address, using `lws::config::network`
        for the tag.
    */
    expect<account_address> operator()(boost::string_ref address) const noexcept;
  };
  constexpr const address_string_ address_string{};
} // db
} // lws
