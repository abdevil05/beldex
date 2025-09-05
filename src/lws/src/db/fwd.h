#pragma once

#include <cstdint>

namespace lws
{
namespace db
{
  enum account_flags : std::uint8_t;
  enum class account_id : std::uint32_t;
  enum class account_status : std::uint8_t;
  enum class block_id : std::uint64_t;
  enum extra : std::uint8_t;
  enum class extra_and_length : std::uint8_t;
  enum class request : std::uint8_t;

  struct account;
  struct account_address;
  struct block_info;
  struct key_image;
  struct output;
  struct output_id;
  struct request_info;
  struct spend;
  class storage;
  struct transaction_link;
  struct view_key;
} // db
} // lws
