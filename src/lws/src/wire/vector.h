#pragma once

#include <type_traits>
#include <vector>

#include "wire/traits.h"

namespace wire
{
  template<typename T>
  struct is_array<std::vector<T>>
    : std::true_type
  {};
}