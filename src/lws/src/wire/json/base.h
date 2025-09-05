#pragma once

#include <string>

#include "epee/byte_slice.h"
#include "common/expect.h"  // beldex/src
#include "wire/json/fwd.h"

namespace wire
{
  struct json
  {
    using input_type = json_reader;
    using output_type = json_writer;

    template<typename T>
    static expect<T> from_bytes(std::string&& source);

    template<typename T>
    static epee::byte_slice to_bytes(const T& source);
  };
}

