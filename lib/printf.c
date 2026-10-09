#include <stdio.h>
#include <stdint.h>
#include <limits.h>

typedef struct { char *buffer; size_t size; size_t stored; size_t total; } output_t;
typedef enum { LEN_DEFAULT, LEN_HH, LEN_H, LEN_L, LEN_LL, LEN_Z } length_t;

static void emit(output_t *out, char character) { if (out->size && out->stored + 1u < out->size) out->buffer[out->stored++] = character; if (out->total < SIZE_MAX) out->total++; }
static void repeat(output_t *out, char character, int count) { while (count-- > 0) emit(out, character); }
static int parse_decimal(const char **format) { int value = 0; while (**format >= '0' && **format <= '9') { int digit = **format - '0'; value = value > (INT_MAX - digit) / 10 ? INT_MAX : value * 10 + digit; (*format)++; } return value; }
static size_t digits(uint64_t value, unsigned base) { size_t count = 1; while (value >= base) { value /= base; count++; } return count; }
static void write_number(output_t *out, uint64_t value, unsigned base, int upper, int width, int precision, int left, int zero, char sign, const char *prefix) {
    char reverse[32]; size_t count = 0; size_t raw = (precision == 0 && value == 0) ? 0 : digits(value, base);
    size_t required = raw > (size_t)(precision < 0 ? 0 : precision) ? raw : (size_t)(precision < 0 ? 0 : precision);
    size_t prefix_size = prefix ? 2u : 0u; if (sign) prefix_size++;
    int padding = width > (int)(required + prefix_size) ? width - (int)(required + prefix_size) : 0;
    if (!left && !(zero && precision < 0)) repeat(out, ' ', padding);
    if (sign) emit(out, sign); if (prefix) { emit(out, prefix[0]); emit(out, prefix[1]); }
    if (!left && zero && precision < 0) repeat(out, '0', padding);
    repeat(out, '0', (int)(required - raw));
    while (raw--) { unsigned digit = (unsigned)(value % base); reverse[count++] = (char)(digit < 10u ? ('0' + digit) : ((upper ? 'A' : 'a') + digit - 10u)); value /= base; }
    while (count) emit(out, reverse[--count]);
    if (left) repeat(out, ' ', padding);
}

int vsnprintf(char *buffer, size_t size, const char *format, va_list arguments) {
    output_t out = { buffer, size, 0, 0 };
    for (; *format; format++) {
        if (*format != '%') { emit(&out, *format); continue; }
        format++;
        int left = 0, plus = 0, space = 0, alternate = 0, zero = 0;
        int more = 1;
        while (more) { switch (*format) { case '-': left = 1; format++; break; case '+': plus = 1; format++; break; case ' ': space = 1; format++; break; case '#': alternate = 1; format++; break; case '0': zero = 1; format++; break; default: more = 0; break; } }
        int width = *format == '*' ? (format++, va_arg(arguments, int)) : parse_decimal(&format); if (width < 0) { left = 1; width = width == INT_MIN ? INT_MAX : -width; }
        int precision = -1; if (*format == '.') { format++; precision = *format == '*' ? (format++, va_arg(arguments, int)) : parse_decimal(&format); if (precision < 0) precision = -1; }
        length_t length = LEN_DEFAULT; if (*format == 'h') { format++; length = *format == 'h' ? (format++, LEN_HH) : LEN_H; } else if (*format == 'l') { format++; length = *format == 'l' ? (format++, LEN_LL) : LEN_L; } else if (*format == 'z') { format++; length = LEN_Z; }
        char conversion = *format; if (!conversion) break;
        if (conversion == '%') { emit(&out, '%'); continue; }
        if (conversion == 'c') { char value = (char)va_arg(arguments, int); int pad = width > 1 ? width - 1 : 0; if (!left) repeat(&out, ' ', pad); emit(&out, value); if (left) repeat(&out, ' ', pad); continue; }
        if (conversion == 's') { const char *text = va_arg(arguments, const char *); if (!text) text = "(null)"; size_t count = 0; while (text[count] && (precision < 0 || count < (size_t)precision)) count++; int pad = width > (int)count ? width - (int)count : 0; if (!left) repeat(&out, ' ', pad); for (size_t i = 0; i < count; i++) emit(&out, text[i]); if (left) repeat(&out, ' ', pad); continue; }
        uint64_t value; int signed_conversion = conversion == 'd' || conversion == 'i';
        if (conversion == 'p') { value = (uintptr_t)va_arg(arguments, void *); write_number(&out, value, 16, 0, width, precision, left, zero, 0, "0x"); continue; }
        if (!(signed_conversion || conversion == 'u' || conversion == 'x' || conversion == 'X')) { emit(&out, '%'); emit(&out, conversion); continue; }
        char sign = 0;
        if (signed_conversion) {
            long long raw;
            if (length == LEN_LL) raw = va_arg(arguments, long long);
            else if (length == LEN_L) raw = va_arg(arguments, long);
            else if (length == LEN_Z) raw = (long long)va_arg(arguments, ptrdiff_t);
            else if (length == LEN_H) raw = (short)va_arg(arguments, int);
            else if (length == LEN_HH) raw = (signed char)va_arg(arguments, int);
            else raw = va_arg(arguments, int);
            if (raw < 0) { sign = '-'; value = (uint64_t)(-(raw + 1LL)) + 1u; } else { value = (uint64_t)raw; sign = plus ? '+' : (space ? ' ' : 0); }
        } else if (length == LEN_LL) value = va_arg(arguments, unsigned long long);
        else if (length == LEN_L) value = va_arg(arguments, unsigned long);
        else if (length == LEN_Z) value = (uint64_t)va_arg(arguments, size_t);
        else if (length == LEN_H) value = (unsigned short)va_arg(arguments, unsigned int);
        else if (length == LEN_HH) value = (unsigned char)va_arg(arguments, unsigned int);
        else value = va_arg(arguments, unsigned int);
        unsigned base = (conversion == 'x' || conversion == 'X') ? 16u : 10u;
        const char *prefix = alternate && value && base == 16u ? (conversion == 'X' ? "0X" : "0x") : 0;
        write_number(&out, value, base, conversion == 'X', width, precision, left, zero, sign, prefix);
    }
    if (size) buffer[out.stored] = 0;
    return out.total > (size_t)INT_MAX ? INT_MAX : (int)out.total;
}
int snprintf(char *buffer, size_t size, const char *format, ...) { va_list arguments; va_start(arguments, format); int result = vsnprintf(buffer, size, format, arguments); va_end(arguments); return result; }
