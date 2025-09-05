#pragma once

#include <type_traits>
#include <utility>

namespace wire
{
  template<bool C>
  using enable_if = typename std::enable_if<C>::type;

  template<typename T>
  struct is_array : std::false_type
  {};

  template<typename T>
  struct is_blob : std::false_type
  {};
}