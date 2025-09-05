#include "error.h"

namespace wire
{
namespace error
{
  const char* get_string(const rapidjson_e value) noexcept
  {
    switch (rapidjson::ParseErrorCode(value))
    {
    default:
      break;

    case rapidjson::kParseErrorNone:
      return "No JSON parsing errors";

      // from rapidjson
    case rapidjson::kParseErrorDocumentEmpty:
      return "JSON parser expected non-empty document";
    case rapidjson::kParseErrorDocumentRootNotSingular:
      return "JSON parser expected one value at root level";

    case rapidjson::kParseErrorValueInvalid:
      return "JSON parser found invalid value";

    case rapidjson::kParseErrorObjectMissName:
      return "JSON parser expected name for object field";
    case rapidjson::kParseErrorObjectMissColon:
      return "JSON parser expected ':' between name and value";
    case rapidjson::kParseErrorObjectMissCommaOrCurlyBracket:
      return "JSON parser expected ',' or '}'";

    case rapidjson::kParseErrorArrayMissCommaOrSquareBracket:
      return "JSON parser expected ',' or ']'";

    case rapidjson::kParseErrorStringUnicodeEscapeInvalidHex:
      return "JSON parser found invalid unicode escape";
    case rapidjson::kParseErrorStringUnicodeSurrogateInvalid:
      return "JSON parser found invalid unicode surrogate value";
    case rapidjson::kParseErrorStringEscapeInvalid:
      return "JSON parser found invalid escape sequence in string value";
    case rapidjson::kParseErrorStringMissQuotationMark:
      return "JSON parser expected '\"'";
    case rapidjson::kParseErrorStringInvalidEncoding:
      return "JSON parser found invalid encoding";

    case rapidjson::kParseErrorNumberTooBig:
      return "JSON parser found number value larger than double float precision";
    case rapidjson::kParseErrorNumberMissFraction:
      return "JSON parser found number missing fractional component";
    case rapidjson::kParseErrorNumberMissExponent:
      return "JSON parser found number missing exponent";

    case rapidjson::kParseErrorTermination:
      return "JSON parser was stopped";
    case rapidjson::kParseErrorUnspecificSyntaxError:
      return "JSON parser found syntax error";
    }

    return "Unknown JSON parser error";
  }

  const std::error_category& rapidjson_category() noexcept
  {
    struct category final : std::error_category
    {
      virtual const char* name() const noexcept override final
      {
        return "wire::error::rapidjson_category()";
      }

      virtual std::string message(int value) const override final
      {
        return get_string(rapidjson_e(value));
      }
    };
    static const category instance{};
    return instance;
  }
} // error
} // wire
