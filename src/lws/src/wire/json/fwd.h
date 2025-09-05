#pragma once

#define WIRE_JSON_DECLARE_ENUM(type)		\
  const char* get_string(type) noexcept;        \
  void read_bytes(::wire::json_reader&, type&);	\
  void write_bytes(:wire::json_writer&, type)

#define WIRE_JSON_DECLARE_OBJECT(type)			\
  void read_bytes(::wire::json_reader&, type&);         \
  void write_bytes(::wire::json_writer&, const type&)

namespace wire
{
  struct json;
  class json_reader;
  class json_writer;
}