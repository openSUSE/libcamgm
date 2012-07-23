%{
#include <ca-mgm/Exception.hpp>
#include <stdexcept>
#include <typeinfo>
%}

%include <exception.i>

#ifdef SWIGPERL5
%{

static SWIGINLINE void
CA_MGM_buildExceptionHash(SWIG_MAYBE_PERL_OBJECT HV * hash, const ca_mgm::Exception &e) {

    SV * value = newSVpv(e.type(), 0);
    hv_store(hash, "type", 4, value, 0);

    value = newSViv(e.getErrorCode());
    hv_store(hash, "code", 4, value, 0);

    value = newSVpv(e.getMessage(), 0);
    hv_store(hash, "message", 7, value, 0);

    value = newSVpv(e.getFile(), 0);
    hv_store(hash, "file", 4, value, 0);

    value = newSViv(e.getLine());
    hv_store(hash, "line", 4, value, 0);

}

static SWIGINLINE void
CA_MGM_croak(SWIG_MAYBE_PERL_OBJECT const ca_mgm::Exception &e) {

    HV * hash  = newHV();

#ifdef PERL_OBJECT
    CA_MGM_buildExceptionHash(pPerl, hash, e);
#else
    CA_MGM_buildExceptionHash(hash, e);
#endif

    sv_setsv(perl_get_sv("@", TRUE), sv_bless(newRV_noinc((SV*)hash), gv_stashpv("CAMGM:Exception", GV_ADD)));
}

#define CA_MGM_exception(a)  { CA_MGM_croak(a); SWIG_fail; }


static SWIGINLINE void
CA_MGM_croak2(SWIG_MAYBE_PERL_OBJECT const std::exception &e) {

    HV * hash  = newHV();

    SV * value = newSVpv(typeid(e).name(), 0);
    hv_store(hash, "type", 4, value, 0);

    value = newSVpv(e.what(), 0);
    hv_store(hash, "message", 7, value, 0);

    sv_setsv(perl_get_sv("@", TRUE), sv_bless(newRV_noinc((SV*)hash), gv_stashpv("CAMGM::Exception", GV_ADD)));
}

#define CA_MGM_exception2(a)  { CA_MGM_croak2(a); SWIG_fail; }

%}

#endif


%exception {
        try {
                $action
        } catch(const ca_mgm::Exception &e) {
            CA_MGM_exception(e);
        } catch(const std::exception &e) {
            CA_MGM_exception2(e);
        } catch(...) {
            SWIG_exception(SWIG_UnknownError, "UnknownError");
            SWIG_fail;
        }
}
