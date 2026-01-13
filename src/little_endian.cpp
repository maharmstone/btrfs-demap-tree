module;

#include <format>

export module little_endian;

using namespace std;

export template<integral T>
class little_endian {
public:
    little_endian() = default;

    constexpr little_endian(T t) {
        for (unsigned int i = 0; i < sizeof(T); i++) {
            val[i] = t & 0xff;
            t >>= 8;
        }
    }

    constexpr operator T() const {
        T t = 0;

#pragma GCC unroll 8
        for (unsigned int i = 0; i < sizeof(T); i++) {
            t <<= 8;
            t |= val[sizeof(T) - i - 1];
        }

        return t;
    }

    little_endian<T>& operator=(T t) {
        for (unsigned int i = 0; i < sizeof(T); i++) {
            val[i] = t & 0xff;
            t >>= 8;
        }

        return *this;
    }

    template<integral T2>
    little_endian<T>& operator &=(const T2& b) {
        *this = (T)*this & b;

        return *this;
    }

    template<integral T2>
    little_endian<T>& operator |=(const T2& b) {
        *this = (T)*this | b;

        return *this;
    }

    template<integral T2>
    little_endian<T>& operator ^=(const T2& b) {
        *this = (T)*this ^ b;

        return *this;
    }

    little_endian<T>& operator++(int) {
        *this = (T)*this + 1;

        return *this;
    }

    little_endian<T>& operator--(int) {
        *this = (T)*this - 1;

        return *this;
    }

    little_endian<T>& operator +=(integral auto b) {
        *this = (T)*this + b;

        return *this;
    }

    little_endian<T>& operator -=(integral auto b) {
        *this = (T)*this - b;

        return *this;
    }

    little_endian<T>& operator *=(integral auto b) {
        *this = (T)*this * b;

        return *this;
    }

    little_endian<T>& operator /=(integral auto b) {
        *this = (T)*this / b;

        return *this;
    }

    little_endian<T>& operator %=(integral auto b) {
        *this = (T)*this % b;

        return *this;
    }

private:
    uint8_t val[sizeof(T)];
} __attribute__((packed));

template<integral T>
struct std::formatter<little_endian<T>> {
    constexpr auto parse(format_parse_context& ctx) {
        formatter<int> f;
        auto it = ctx.begin();
        auto ret = f.parse(ctx);

        fmt = "{:"s + string{string_view(it, ret - it)} + "}"s;

        return ret;
    }

    template<typename format_context>
    auto format(little_endian<T> t, format_context& ctx) const {
        auto num = (T)t;

        return vformat_to(ctx.out(), fmt, make_format_args(num));
    }

    string fmt;
};
