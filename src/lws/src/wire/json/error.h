#pragma once

#include <rapidjson/error/error.h>
#include <system_error>

namespace wire
{
namespace error
{
  //! Type wrapper to "grab" rapidjson errors
  enum class rapidjson_e : int {};

  //! \return Static string describing error `value`.
  const char* get_string(rapidjson_e value) noexcept;

  //! \return Category for rapidjson generated errors.
  const std::error_category& rapidjson_category() noexcept;

  //! \return Error code with `value` and `rapidjson_category()`.
  inline std::error_code make_error_code(rapidjson_e value) noexcept
  {
    return std::error_code{int(value), rapidjson_category()};
  }
}
}