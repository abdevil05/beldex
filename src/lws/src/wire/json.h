#pragma once

#include "wire/json/base.h"
#include "wire/json/error.h"
#include "wire/json/read.h"
#include "wire/json/write.h"

#define WIRE_JSON_DEFINE_ENUM(type, map)				\
  void read_bytes(::wire::json_reader& source, type& dest)		\
  {									\
    dest = type(source.enumeration(map));				\
  }									\
  void write_bytes(::wire::json_writer& dest, const type source)	\
  {									\
    dest.enumeration(std::size_t(source), map);				\
  }

#define WIRE_JSON_DEFINE_OBJECT(type, map)                              \
  void read_bytes(::wire::json_reader& source, type& dest)              \
  {                                                                     \
    map(source, dest);                                                  \
  }                                                                     \
  void write_bytes(::wire::json_writer& dest, const type& source)       \
  {                                                                     \
    map(dest, source);                                                  \
  }
