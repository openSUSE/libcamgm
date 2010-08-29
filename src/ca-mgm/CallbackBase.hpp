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

  File:       CallbackBase.hpp

  Author:     Marius Tomaschewski
  Maintainer: Marius Tomaschewski

/-*/
/**
 * @file   CallbackBase.hpp
 * @brief  LiMaL callback interface.
 *
 * Provides an abstract template base class for the callback
 * interface supported in LiMaL.
 */
#ifndef   CA_MGM_CALLBACK_BASE_HPP
#define   CA_MGM_CALLBACK_BASE_HPP

#include <ca-mgm/config.h>


namespace CA_MGM_NAMESPACE
{

// -------------------------------------------------------------------
/**
 * @brief LiMaL callback interface base class.
 *
 * The abstract CallbackBase template provides the callback
 * interface supported in LiMaL.
 *
 * The interface uses only one callback function signature (see
 * callback() method), but with definable return code and input
 * parameter data-types (Request,Result).
 * Both data-types have the requirement to provide a default and
 * (deep) copy constructors. The default constructor can be used
 * to signal default or invalid Request/Result.
 *
 * The usage of one function signature and the copy constructor
 * make it possible to implement reusable support wrapper
 * templates allowing to implement the callback method in
 * languages other than C++ (e.g. perl or python).
 *
 * To implement a function (or class) using a callback, following
 * steps are required:
 *
 *  - Declare and implement one or two classes that will be used
 *    as Request (input parameters) and the Result (return value)
 *    types by the callback method. For example:
 *    @code
 *       class DoitCBMsg
 *       {
 *       private:
 *           int foo;
 *       public:
 *           DoitCBMsg(int arg=0): foo(arg) {}
 *           DoitCBMsg(const DoitCBMsg &msg): foo(msg.foo) {}
 *           ~DoitCBMsg() {}
 *           int getFoo() { return foo; }
 *       };
 *    @endcode
 *  .
 *
 *  - Declare and implement your function using a callback with
 *    the previously declared Request and Result types:
 *    @code
 *      // specialize the callback interface for Request/Result
 *      typedef CallbackBase<DoitCBMsg,DoitCBMsg> DoitCB;
 *
 *      // use the specialized callback type in the caller function
 *      int doit(DoitCB *cb)
 *      {
 *          if(cb)
 *          {
 *              DoitCBMsg  request(42);
 *              DoitCBMsg *result = NULL;
 *              try
 *              {
 *                  result = cb->call(&request);
 *              }
 *              // ...
 *          }
 *          return 1;
 *      }
 *    @endcode
 *  .
 *
 *  - The user of the function using a callback has to inherit
 *    from the specialized callback class (DoitCB in the example)
 *    and implement the abstract callback() method and pass an
 *    instance of the derived class to the function. For example:
 *    @code
 *      // implement callback derived from specialized class
 *      class MyDoitCB: public DoitCB
 *      {
 *      private:
 *          int m_data; // some internal data if / as required
 *
 *      public:
 *          MyDoitCB(int data): DoitCB(), m_data(data)   {}
 *          ~MyDoitCB()                                  {}
 *
 *          // implement the callback method and functionality
 *          virtual Result *
 *          callback(const Request *request)
 *          {
 *              if( request)
 *                  return new Result(request->getFoo() * m_data);
 *              else
 *                  return new Result();
 *          }
 *      };
 *
 *      int main(void)
 *      {
 *          // create callback instance
 *          MyDoitCB cb(2);
 *
 *          // pass it to the function using it
 *          int ret = doit(&cb);
 *
 *          return 0;
 *      }
 *    @endcode
 *  .
 *
 * @todo Implement a CallbackRef holding a reference counted
 *       (specialized?) Callback object...
 * @todo Implement a call() method variant using Request/Result
 *       references?
 */
template <class Request, class Result>
class CallbackBase
{
public:
	/**
	 * Default constructor.
	 */
	CallbackBase()
	{}

	/**
	 * Destructor.
	 */
	virtual ~CallbackBase()
	{}

	/**
	 * Call method for the caller function executing a callback.
	 *
	 * @param request Read-Only pointer to the callback request.
	 * @return A pointer to a new result object returned by the
	 *         callback method or NULL in case of execution errors.
	 *         The object has to be deleted by the caller if not
	 *         longer needed.
	 * @throws std::bad_alloc and maybe other, callback() method
	 *         implementation specific exceptions.
	 */
	virtual Result *
	call(const Request *request)
	{
		return callback(request);
	}

protected:

	/**
	 * Callback method that has to be implemented by the user
	 * and delivers the result for to the request back to the
	 * caller.
	 *
	 * @param request Read-Only pointer to the callback request.
	 * @return A pointer to a new result object or NULL for
	 *         execution error conditions. The object will be
	 *         deleted by the caller.
	 * @throws std::bad_alloc and maybe other, implementation
	 *         specific exceptions.
	 */
	virtual Result *
	callback(const Request *request) = 0;

private:
	/**
	 * Copying not allowed.
	 */
	CallbackBase(const CallbackBase &);

	/**
	 * Copying not allowed.
	 */
	CallbackBase & operator = (const CallbackBase &);
};


// -------------------------------------------------------------------
}      // End of CA_MGM_NAMESPACE
#endif // CA_MGM_CALLBACK_BASE_HPP
// vim: set ts=8 sts=8 sw=8 ai noet:
