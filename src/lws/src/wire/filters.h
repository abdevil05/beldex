#pragma once

#include <cassert>
#include <type_traits>

#include "lmdb/util.h"

// These functions are to be used with `wire::as_object(...)` key filtering

namespace wire
{
  //! Callable that returns the value unchanged; default filter for `as_array` and `as_object`.
  struct identity_
  {
    template<typename T>
    const T& operator()(const T& value) const noexcept
    {
      return value;
    }
  };
  constexpr const identity_ identity{};

  //! Callable that forwards enum to get_string.
  struct enum_as_string_
  {
    template<typename T>
    auto operator()(const T value) const noexcept(noexcept(get_string(value))) -> decltype(get_string(value))
    {
      return get_string(value);
    }
  };
  constexpr const enum_as_string_ enum_as_string{};

  //! Callable that converts C++11 enum class or integer to integer value.
  struct as_integer_
  {
    template<typename T>
    lmdb::native_type<T> operator()(const T value) const noexcept
    {
      using native = lmdb::native_type<T>;
      static_assert(!std::is_signed<native>::value, "integer cannot be signed");
      return native(value);
    }
  };
  constexpr const as_integer_ as_integer{};
}
