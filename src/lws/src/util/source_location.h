#pragma once
#include <iosfwd>

//! Expands to an object that tracks current source location
#define MLWS_CURRENT_LOCATION ::lws::source_location{__FILE__, __LINE__}

namespace lws
{
  //! Tracks source location in one object, with `std::ostream` output.
  class source_location
  {
    // NOTE This is available in newer Boost versions
    const char* file_;
    int line_;

  public:
    constexpr source_location() noexcept
      : file_(nullptr), line_(0)
    {}

    //! `file` must be in static memory
    constexpr source_location(const char* file, int line) noexcept
      : file_(file), line_(line)
    {}

    source_location(const source_location&) = default;
    source_location& operator=(const source_location&) = default;

    //! \return Possibly `nullptr`, otherwise full file path
    const char* file_name() const noexcept { return file_; }
    int line() const noexcept { return line_; }
  };

  //! Prints `loc.file_name() + ':' + loc.line()`
  std::ostream& operator<<(std::ostream& os, source_location loc);
}
