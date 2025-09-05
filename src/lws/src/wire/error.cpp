#include "wire/error.h"

namespace wire
{
  namespace error
  {
    const char* get_string(const schema value) noexcept
    {
      switch (value)
      {
      default:
        break;

      case schema::none:
        return "No schema errors";
      case schema::array:
        return "Schema expected array";
      case schema::binary:
        return "Schema expected binary value of variable size";
      case schema::boolean:
        return "Schema expected boolean value";
      case schema::enumeration:
        return "Schema expected a specific of enumeration value(s)";
      case schema::fixed_binary:
        return "Schema expected binary of fixed size";
      case schema::integer:
        return "Schema expected integer value";
      case schema::invalid_key:
        return "Schema does not allow object field key";
      case schema::larger_integer:
        return "Schema expected a larger integer value";
      case schema::maximum_depth:
        return "Schema hit maximum array+object depth tracking";
      case schema::missing_key:
        return "Schema missing required field key";
      case schema::number:
        return "Schema expected number (integer or float) value";
      case schema::object:
        return "Schema expected object";
      case schema::smaller_integer:
        return "Schema expected a smaller integer value";
      case schema::string:
        return "Schema expected string";
      }
      return "Unknown schema error";
    }

    const std::error_category& schema_category() noexcept
    {
      struct category final : std::error_category
      {
        virtual const char* name() const noexcept override final
          {
            return "wire::error::schema_category()";
          }

          virtual std::string message(int value) const override final
          {
            return get_string(schema(value));
          }
      };
      static const category instance{};
      return instance;
    }
  }
}
