/* This file contains a generic definition of blocxx::Map along with
 * some helper functions.  Specific language modules should include
 * this file to generate wrappers.
 */

%{
#include <map>
%}

%include "camgm_exceptions.i"

%exception std::map::getitem {
    try {
        $action
    } catch (std::out_of_range& e) {
        SWIG_exception(SWIG_IndexError,const_cast<char*>(e.what()));
    }
}

%exception std::map::delitem  {
    try {
        $action
    } catch (std::out_of_range& e) {
        SWIG_exception(SWIG_IndexError,const_cast<char*>(e.what()));
    }
}

%define %std_map_methods(K, T)
       typedef T&                         reference;
       typedef const T&                   const_reference;
       typedef map<K, T>::const_iterator  const_iterator;

       map();
       map(const map<K, T> &);
      ~map();

       void swap(map<K, T> &x);
       size_t size() const;
       size_t max_size() const;
       bool empty() const;
       void clear();
       const_iterator   begin () const;
       const_iterator   end () const;


       /* Some useful extensions */
       %extend {
          void iterator_incr(const_iterator *it ) {
                (*it)++;
           }
           void iterator_decr(const_iterator *it) {
                (*it)--;
           }
           bool iterator_equal(const_iterator it1, const_iterator it2) {
                return (it1 == it2);
           }
           K iterator_key(const_iterator it) {
                return ((*it).first);
           }
           T iterator_value(const_iterator it) {
                return ((*it).second);
           }
           bool contains(const K &key) const {

                return (self->find(key) == self->end()) ? false : true;

           }
           const T& getitem(const K &key) const {
                std::map<K,T >::const_iterator i = self->find(key);
                if (i != self->end())
                    return i->second;
                else
                    throw std::out_of_range("key not found");
           }
           void setitem(const K& key, const T& x) {
               (*self)[key] = x;
           }
           void delitem(const K& key) {
               std::map<K,T >::iterator i = self->find(key);
               if (i != self->end())
                   self->erase(i);
               else
                   throw std::out_of_range("key not found");
           }
       };

%enddef

namespace std {
template<class K, class T> class map {
public:
   %std_map_methods(K, T);
};
}


