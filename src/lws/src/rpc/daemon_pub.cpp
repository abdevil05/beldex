#include "daemon_pub.h"

#include "wire/crypto.h"
#include "wire/error.h"
#include "wire/field.h"
#include "wire/traits.h"
#include "wire/json/read.h"

namespace
{
  struct dummy_chain_array
  {
    using value_type = crypto::hash;

    std::uint64_t count;
    std::reference_wrapper<crypto::hash> id;

    void clear() noexcept {}
    void reserve(std::size_t) noexcept {}

    crypto::hash& back() noexcept { return id; }
    void emplace_back() { ++count; }
  };
}

namespace wire
{
  template<>
  struct is_array<dummy_chain_array>
    : std::true_type
  {};
}

namespace lws
{
namespace rpc
{
  static void read_bytes(wire::json_reader& src, minimal_chain_pub& self)
  {
    dummy_chain_array chain{0, std::ref(self.top_block_id)};
    wire::object(src,
      wire::field("first_height", std::ref(self.top_block_height)),
      wire::field("ids", std::ref(chain))
    );

    self.top_block_height += chain.count - 1;
    if (chain.count == 0)
      WIRE_DLOG_THROW(wire::error::schema::binary, "expected at least one block hash");
  }

  expect<minimal_chain_pub> minimal_chain_pub::from_json(std::string&& source)
  {
    return wire::json::from_bytes<minimal_chain_pub>(std::move(source));
  }
}
}
