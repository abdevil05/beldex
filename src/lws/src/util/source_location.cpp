#include <cstring>
#include <ostream>
#include "util/source_location.h"

namespace lws
{
  std::ostream& operator<<(std::ostream& os, const source_location loc)
  {
    if (loc.line())
    {
      char const* const just_name = loc.file_name() ?
        std::strrchr(loc.file_name(), '/') : nullptr;
      os << (just_name ? just_name + 1 : loc.file_name()) << ':' << loc.line();
    }
    else
      os << "(unknown source location)";
    return os;
  }
}
