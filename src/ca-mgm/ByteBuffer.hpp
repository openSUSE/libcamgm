/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                             core library                             |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       ByteBuffer.hpp

  Maintainer: Michael Calmer

/-*/
/**
 * @file   ByteBuffer.hpp
 * @brief  LiMaL byte buffer class.
 *
 * Provides a ByteBuffer class for storage and manipulation
 * of memory areas with custom data.
 */
#ifndef CA_MGM_BYTEBUFFER_HPP
#define CA_MGM_BYTEBUFFER_HPP

#include <ca-mgm/config.h>
#include <ca-mgm/PtrTypes.hpp>
#include <iostream>
extern "C"
{
#include <sys/types.h>
}

namespace CA_MGM_NAMESPACE
{

    /*
     * Forward declaration.
     */
    class ByteBufferImpl;


    /**
     * @brief Buffer for storing binary data.
     *
     * The class implements a byte buffer useful for manipulating memory
     * areas with custom data.
     *
     * It is reference counted and supports copy on write functionality.
     *
     */
    class ByteBuffer
    {
    public:

        /**
         * Create an empty ByteBuffer object.
         */
        ByteBuffer();

        /**
         * Create a ByteBuffer object and initialize it with the C string
         * provided in <b>str</b>. The size is determined using the
         * <b>::strlen(str)</b> function.
         *
         * @param str Pointer to a '\\0' terminated C string.
         * @throws std::bad_alloc
         */
        ByteBuffer(const char *str);

        /**
         * Create a ByteBuffer object that will contain a copy of the given
         * character array <b>ptr</b> and its size given in <b>len</b>.
         *
         * @param ptr Pointer to a character array to copy from.
         * @param len The length of the character array in <b>ptr</b>.
         * @throws std::bad_alloc
         */
        ByteBuffer(const char *ptr, size_t len);

        /**
         * Create a new ByteBuffer object that is a shared copy of an
         * another ByteBuffer object.
         *
         * Upon return, both objects will point to the same underlying
         * byte buffer. This state will remain until one of the objects
         * is modified (copy on write).
         *
         * @param The ByteBuffer object to make a copy of.
         */
        ByteBuffer(const ByteBuffer &buf);

        /**
         * Destroy the ByteBuffer object.
         */
        ~ByteBuffer();

        /**
         * @brief Remove all data from the ByteBuffer.
         *
         * The size() of the ByteBuffer should be zero after calling this
         * method.
         * @throws  std::bad_alloc
         */
        void        clear();

        /**
         * @brief Return true if the ByteBuffer is empty (size() == 0)
         */
        bool        empty() const;

        /**
         * @brief Return the number of bytes in this ByteBuffer
         *
         * @return The number of bytes in this ByteBuffer.
         */
        size_t      size() const;

        /**
         * @brief Returns a pointer to the data stored in the ByteBuffer.
         *
         * @return Returns a pointer to the data.
         */
        const char* data() const;

        /**
         * @brief Return the byte at position <b>pos</b>.
         *
         * @return Return the byte at position <b>pos</b>.
         * @throws ca_mgm::OutOfBoundsException if the position is bigger
         *         than the number of bytes in this ByteBuffer.
         */
        char        at(size_t pos) const;

        /**
         * @brief Append new data to this ByteBuffer object
         *
         * @param ptr Pointer to a character array to copy from.
         * @param len The length of the character array in <b>ptr</b>.
         * @throws std::bad_alloc
         */
        void        append(const char *ptr, size_t len);

        /**
         * @brief Append a new byte to this ByteBuffer object
         *
         * @param c The new byte to append.
         * @throws std::bad_alloc
         */
        void        append(char c);

#ifndef SWIG

        /**
         * @brief Assigns <b>buf</b> to this ByteBuffer object.
         *
         * Assigns <b>buf</b> to this ByteBuffer object and returns
         * a reference to this ByteBuffer object.
         *
         * @param buf The ByteBuffer object to assign
         * @return    A reference to this ByteBuffer object
         * @throws    std::bad_alloc
         */
        ByteBuffer& operator=(const ByteBuffer& buf);

        /**
         * @brief Return the byte at position <b>pos</b>
         *
         * @param pos The position of the byte which should be returned.
         * @return    Read-Only reference to the byte at the specified
         *            position <b>pos</b>.
         * @throws    ca_mgm::OutOfBoundsException if position is bigger
         *            than the size of this ByteBuffer.
         */
        const char& operator[](size_t pos) const;

        /**
         * @brief Return the byte at position <b>pos</b>
         *
         * @param pos The position of the byte which should be returned.
         * @return    Read-Write reference to the byte at the specified
         *            position <b>pos</b>.
         * @throws    ca_mgm::OutOfBoundsException if position is bigger
         *            than the size of this ByteBuffer.
         */
        char& operator[](size_t pos);

        /**
         * @brief Appends data from the ByteBuffer object <b>buf</b>.
         *
         * Appends data from the specified ByteBuffer object <b>buf</b>
         * to the end of this ByteBuffer object and returns a reference
         * to this ByteBuffer object.
         *
         * @param buf The ByteBuffer object to append.
         * @return    A reference to this ByteBuffer object.
         * @throws    std::bad_alloc
         */
        ByteBuffer& operator+=(const ByteBuffer& buf);


        // friends

        /**
         * A stream output operator for debugging purposes.
         */
        friend std::ostream& operator<<(std::ostream &out,
                                        const ByteBuffer &buf);

        /**
         * @return True if the ByteBuffer object <b>l</b> is equal
         * to the ByteBuffer object <b>r</b>; otherwise false.
         */
        friend bool operator==(const ByteBuffer &l, const ByteBuffer &r);

        /**
         * @return True if the ByteBuffer object <b>l</b> is not equal
         * to the ByteBuffer object <b>r</b>; otherwise false.
         */
        friend bool operator!=(const ByteBuffer &l, const ByteBuffer &r);

        /**
         * @return True if the ByteBuffer object <b>l</b> is less than
         * the ByteBuffer object <b>r</b>; otherwise false.
         */
        friend bool operator<(const ByteBuffer &l, const ByteBuffer &r);

        /**
         * @return True if the ByteBuffer object <b>l</b> is greater than
         * the ByteBuffer object <b>r</b>; otherwise false.
         */
        friend bool operator>(const ByteBuffer &l, const ByteBuffer &r);

        /**
         * @return True if the ByteBuffer object <b>l</b> is less than
         * or equal to the ByteBuffer object <b>r</b>; otherwise false.
         */
        friend bool operator<=(const ByteBuffer &l, const ByteBuffer &r);

        /**
         * @return True if the ByteBuffer object <b>l</b> is greater then
         * or equal to the ByteBuffer object <b>r</b>; otherwise false.
         */
        friend bool operator>=(const ByteBuffer &l, const ByteBuffer &r);

        /**
         * @return   A ByteBuffer object that is the result of concatenating
         *           the ByteBuffer object <b>b1</b> and the ByteBuffer object
         *           <b>b2</b>.
         * @throws   std::bad_alloc
         */
        friend ByteBuffer operator+(const ByteBuffer& b1, const ByteBuffer& b2);

#endif

    private:
        ca_mgm::RWCOW_pointer<ByteBufferImpl> m_impl;
    };

}      // End Of CA_MGM_NAMESPACE
#endif // CA_MGM_BYTEBUFFER_HPP
