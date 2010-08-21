/* This file contains a generic definition of blocxx::Array along with
 * some helper functions.  Specific language modules should include
 * this file to generate wrappers.
 */

%{
#include <vector>
#include <stdexcept>
%}

%include "camgm_exceptions.i"

%define %std_vector_methods(T)
       typedef T&                         reference;
       typedef const T&                   const_reference;
       typedef vector<T>::iterator         iterator;
       typedef vector<T>::reverse_iterator reverse_iterator;

       vector();
       vector(size_t size, const T& value);
       vector(size_t size);
       vector(const vector<T> &);
       vector(iterator first, iterator last);
      ~vector();

       void             swap(vector<T> &x);
       size_t           size() const;
       size_t           max_size() const;
       size_t           capacity () const;
       void             resize(size_t n);
       void             resize(size_t n,  const T &x);
       void             reserve (size_t n);
       bool             empty() const;
       const_reference  front();
       const_reference  back();
       void             push_back(const T& x);
       /*void             append (const T &x);*/
       void             pop_back();
       void             clear();

       iterator         begin();
       iterator         end();
       reverse_iterator rbegin();
       reverse_iterator rend();

       iterator insert(iterator position, const T &x);
       /* void     insert(size_t   position, const T &x); */
       void     insert(iterator position, iterator first, iterator last);
       /* void     appendArray(const vector< T > &x); */

       iterator erase (iterator position);
       iterator erase (iterator first, iterator last);
       /*
       void     remove(size_t index);
       void     remove(size_t begin, size_t end);
       */

       /* Some useful extensions */
       %extend {
           void iterator_incr(iterator *it ) {
                (*it)++;
           }
           void iterator_decr(iterator *it) {
                (*it)--;
           }
           bool iterator_equal(iterator it1, iterator it2) {
                return (it1 == it2);
           }
           T& iterator_value(iterator it) {
                return (*it);
           }
           const T& getitem(size_t index) {
                return ((*self)[index]);
           }
       };

%enddef

namespace std {
template<class T> class vector {
  public:
    %std_vector_methods(T);
};
}
