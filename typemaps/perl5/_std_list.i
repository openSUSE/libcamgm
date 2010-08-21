/* This file contains a generic definition of list along with
 * some helper functions.  Specific language modules should include
 * this file to generate wrappers.
 */

%{
#include <list>
#include <stdexcept>
%}

%include "camgm_exceptions.i"

%define %std_list_methods(T)
       typedef T&                       reference;
       typedef const T&                 const_reference;
       /* typedef list<T>::const_iterator  const_iterator; */
       typedef list<T>::iterator        iterator;

       list();
       list(size_t size, const T& value=T());
       list(const list<T> &);
      ~list();

       /*void assign(unsigned int n, const T& value);*/
       void swap(list<T> &x);
       size_t size() const;
       size_t max_size() const;
       void resize(unsigned int n, T c = T());
       bool empty() const;
       const_reference front();
       const_reference back();
       void push_front(const T& x);
       void push_back(const T& x);
       void pop_front();
       void pop_back();
       void clear();
       void remove(const T& x);
       void unique();
       void merge(list &x);
       void reverse();
       void sort ();

       iterator begin();
       iterator end();

       iterator insert(iterator position, const T &x);
       void     insert(iterator pos, size_t n, const T &x);
       iterator erase (iterator position);
       iterator erase (iterator first, iterator last);
       void     splice(iterator position, list &x);
       void     splice(iterator position, list &x, iterator i);
       void     splice(iterator position, list &x, iterator first, iterator last);

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
       };

%enddef

namespace std {
template<class T> class list {
  public:
    %std_list_methods(T);
};
}
