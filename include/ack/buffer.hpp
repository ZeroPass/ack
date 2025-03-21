// Copyright © 2023 ZeroPass <zeropass@pm.me>
// Author: Crt Vavros
#pragma once
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <type_traits>

#include <ack/types.hpp>
#include <ack/type_traits.hpp>
#include <ack/utils.hpp>

namespace ack {

    // TODO: Replace std::enable_if_t with concepts when clang 10 is supported
    template<typename Derived, typename ValueType, typename = std::enable_if_t<std::is_integral_v<ValueType>>>
    class buffer_base {
        public:
            using value_type = ValueType;
            using derived_type = Derived;

            constexpr bool resize(size_t n)
            {
                return static_cast<derived_type&>(*this).resize(n);
            }

            constexpr void clear()
            {
                static_cast<derived_type&>(*this).clear();
            }

            constexpr value_type* data()
            {
                return static_cast<derived_type&>(*this).data();
            }

            constexpr const value_type* data() const
            {
                return static_cast<const derived_type&>(*this).data();
            }

            constexpr std::size_t size() const
            {
                return static_cast<const derived_type&>(*this).size();
            }

            constexpr std::size_t max_size() const
            {
                return static_cast<const derived_type&>(*this).max_size();
            }

            constexpr const value_type& operator[](size_t n) const
            {
                return static_cast<const derived_type&>(*this).operator[](n);
            }

            constexpr value_type& operator[](size_t n)
            {
                return static_cast<derived_type&>(*this).operator[](n);
            }

        private:
            buffer_base() = default;
            friend derived_type;
    };

    template<typename T, std::size_t N>
    class fixed_buffer : public buffer_base<fixed_buffer<T, N>, T> {
        public:
            using value_type = T;

            constexpr fixed_buffer() noexcept = default;
            constexpr fixed_buffer(const fixed_buffer& rhs) noexcept = default;
            constexpr fixed_buffer(fixed_buffer&& rhs) noexcept = default;
            constexpr fixed_buffer& operator=(const fixed_buffer& rhs) noexcept = default;
            constexpr fixed_buffer& operator=(fixed_buffer&& rhs) noexcept = default;

            constexpr bool resize(size_t n) noexcept
            {
                if ( n > N ) {
                    return false;
                }
                size_ = n;
                return true;
            }

            constexpr void clear() noexcept
            {
                size_ = 0;
            }

            constexpr T* data() noexcept
            {
                return data_.data();
            }

            constexpr const T* data() const
            {
                return data_.data();
            }

            constexpr std::size_t size() const noexcept
            {
                return size_;
            }

            constexpr std::size_t max_size() const noexcept
            {
                return N;
            }

            constexpr void swap(fixed_buffer& rhs) noexcept
            {
                std::swap( data_, rhs.data_ );
                std::swap( size_, rhs.size_ );
            }

            constexpr const T& operator[](size_t n) const
            {
                check( n < size_, "fixed_buffer:operator[]: overflow" );
                return data_[n];
            }

            constexpr T& operator[](size_t n)
            {
                check( n < size_, "fixed_buffer:operator[]: overflow" );
                return data_[n];
            }

        private:
            std::array<T, N> data_ = {};
            std::size_t size_ = 0;
    };

    /**
     * Flexible buffer which can be constructed at compile time to the size of N.
     * @warning if buffer is resized over the size of stack allocated memory (N)
     *          data is re-allocated on the heap, and this data is never released
     *          due to constexpr constrains which prohibits defining custom destructor.
     *          You have to manually call `clear` to free heap allocated memory.
     *          The flexbuffer should be used only in short lived environments like WASM.
    */
    template<typename T, std::size_t N>
    class flexbuffer final: public buffer_base<flexbuffer<T, N>, T> {
        public:
            using value_type = T;

            constexpr flexbuffer() noexcept = default;
            constexpr flexbuffer(const flexbuffer& rhs)
            {
                sdata_ = rhs.sdata_;
                size_  = rhs.size_;
                dsize_ = rhs.dsize_;
                if ( !std::is_constant_evaluated() ) {
                    if ( rhs.ddata_ ) {
                        ddata_ = new T[dsize_];
                        memcpy( ddata_, rhs.ddata_ , dsize_ * sizeof( T ));
                    }
                }
            }

            constexpr flexbuffer(flexbuffer&& rhs) noexcept
            {
                sdata_ = std::move( rhs.sdata_ );
                size_  = rhs.size_;
                dsize_ = rhs.dsize_;
                ddata_ = rhs.ddata_;

                rhs.size_  = 0;
                rhs.dsize_ = 0;
                rhs.ddata_ = nullptr;
            }

            constexpr flexbuffer& operator=(const flexbuffer& rhs)
            {
                if ( &rhs != this ) {
                    this->clear();
                    sdata_ = rhs.sdata_;
                    size_  = rhs.size_;
                    dsize_ = rhs.dsize_;
                    if ( !std::is_constant_evaluated() ) {
                        if ( rhs.ddata_ ) {
                            ddata_ = new T[dsize_];
                            memcpy( ddata_, rhs.ddata_ , dsize_ * sizeof( T ));
                        }
                    }
                }
                return *this;
            }

            constexpr flexbuffer& operator=(flexbuffer&& rhs) noexcept
            {
                if ( &rhs != this ) {
                    this->clear();
                    sdata_ = std::move( rhs.sdata_ );
                    size_  = rhs.size_;
                    dsize_ = rhs.dsize_;
                    ddata_ = rhs.ddata_;

                    rhs.size_  = 0;
                    rhs.dsize_ = 0;
                    rhs.ddata_ = nullptr;
                }
                return *this;
            }

            // constexpr ~flex_buffer()  // destructor deleted otherwise flex_buffer can't be constructed at compile time
            // {
            //     if ( std::is_constant_evaluated() ) {
            //         if ( ddata_ ) {
            //             delete[] ddata_;
            //         }
            //     }
            // }

            constexpr bool resize(size_t n)
            {
                if ( std::is_constant_evaluated() ) {
                    if ( n > sdata_.size() ) {
                        return false;
                    }
                }
                else {
                    if ( n > N && n > dsize_ ) {
                        const bool scpy = ( ddata_ == nullptr );
                        T* pold = ddata_;

                        dsize_ += std::max( N, n );
                        ddata_ = new T[dsize_];

                        if ( scpy ) {
                            memcpy( ddata_, sdata_.data(), N * sizeof( T ));
                        }
                        else {
                            memcpy( ddata_, pold, (dsize_ - std::max( N, n )) * sizeof( T ));
                            delete[] pold;
                            pold = nullptr;
                        }
                    }
                }

                size_ = n;
                return true;
            }

            constexpr void clear()
            {
                if ( !std::is_constant_evaluated() ) {
                    if ( ddata_ ) {
                        delete [] ddata_;
                        ddata_ = nullptr;
                    }
                }
                dsize_ = 0;
                size_  = 0;
            }

            constexpr T* data()
            {
                return ddata_ ? ddata_ : sdata_.data();
            }

            constexpr const T* data() const
            {
                return ddata_ ? ddata_ : sdata_.data();
            }

            constexpr std::size_t size() const
            {
                return size_;
            }

            constexpr std::size_t max_size() const
            {
                return N + std::numeric_limits<std::ptrdiff_t>::max();//ddata_.max_size();
            }

            constexpr void swap(flexbuffer& rhs)
            {
                std::swap( sdata_, rhs.sdata_ );
                if ( !std::is_constant_evaluated() ) {
                    std::swap( dsize_, rhs.dsize_ );
                    std::swap( ddata_, rhs.ddata_ );
                }
                std::swap( size_, rhs.size_ );
            }

            constexpr const T& operator[](size_t n) const
            {
                check( n < size_, "flexbuffer::operator[]: overflow" );
                if ( std::is_constant_evaluated() ) {
                    return sdata_[n];
                }
                else {
                    return ddata_ ? ddata_[n] : sdata_[n];
                }
            }

            constexpr T& operator[](size_t n)
            {
                check( n < size_, "flexbuffer::operator[]: overflow" );
                if ( std::is_constant_evaluated() ) {
                    return sdata_[n];
                }
                else {
                    return ddata_ ? ddata_[n] : sdata_[n];
                }
            }

        private:
            std::array<T, N> sdata_ = {};
            T* ddata_ = nullptr; // replace with std::vector<T> when C++20 constexpr ctor is supported
            std::size_t size_  = 0;
            std::size_t dsize_ = 0;
    };
    template<std::size_t N>
    using fixed_word_buffer = fixed_buffer<word_t, N>;

    template<std::size_t N>
    using word_buffer = flexbuffer<word_t, N>;
}