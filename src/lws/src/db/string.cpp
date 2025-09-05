#include "string.h"

#include "config.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"  //beldex/src
#include "db/data.h"
#include "error.h"

namespace lws
{
namespace  db
{
  std::string address_string_::operator()(account_address const& address) const
  {
    const cryptonote::account_public_address address_{
      address.spend_public, address.view_public
    };
    return cryptonote::get_account_address_as_str(
      lws::config::network, false, address_
    );
  }
  expect<account_address>
  address_string_::operator()(boost::string_ref address) const noexcept
  {
    cryptonote::address_parse_info info{};

    if (!cryptonote::get_account_address_from_str(info, lws::config::network, std::string{address}))
      return {lws::error::bad_address};
    if (info.is_subaddress || info.has_payment_id)
      return {lws::error::bad_address};

    return account_address{
      info.address.m_view_public_key, info.address.m_spend_public_key
    };
  }
} // db
} // lws