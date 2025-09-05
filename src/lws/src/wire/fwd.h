#pragma once

#include <boost/utility/string_ref.hpp>
#include <type_traits>

#include "common/expect.h" // beldex/src

#define WIRE_AS_INTEGER(type_)						\
  static_assert(std::is_enum<type_>(), "AS_INTEGER only enum types");	\
  template<typename R>							\
  inline void read_bytes(R& source, type_& dest)                        \
  {									\
    std::underlying_type<type_>::type temp{};                           \
    read_bytes(source, temp);                                           \
    dest = type_(temp);                                                 \
  }									\
  template<typename W>							\
  inline void write_bytes(W& dest, const type_ source)			\
  {                                                                     \
    write_bytes(dest, std::underlying_type<type_>::type(source));       \
  }

//! Declare an enum to be serialized as a string (json) or integer (msgpack)
#define WIRE_DECLARE_ENUM(type)                                         \
  const char* get_string(type) noexcept;                                \
  expect<type> type ## _from_string(const boost::string_ref) noexcept; \
  void read_bytes(::wire::reader&, type&);                              \
  void write_bytes(::wire::writer&, type)

//! Declare a class/struct serialization for all available formats
#define WIRE_DECLARE_OBJECT(type)                     \
  void read_bytes(::wire::reader&, type&);            \
  void write_bytes(::wire::writer&, const type&)

namespace wire
{
  class reader;
  struct writer;
}


