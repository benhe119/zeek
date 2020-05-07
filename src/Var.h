// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "IntrusivePtr.h"
#include "ID.h"
#include "Type.h"

class FuncType;
class Scope;
class EventHandlerPtr;
class StringVal;
class TableVal;
class ListVal;

FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);

typedef enum { VAR_REGULAR, VAR_CONST, VAR_REDEF, VAR_OPTION, } decl_type;

extern void add_global(ID* id, IntrusivePtr<BroType> t, init_class c,
                       IntrusivePtr<zeek::detail::Expr> init, attr_list* attr, decl_type dt);

extern IntrusivePtr<zeek::detail::Stmt> add_local(IntrusivePtr<ID> id,
                                    IntrusivePtr<BroType> t, init_class c,
                                    IntrusivePtr<zeek::detail::Expr> init, attr_list* attr,
                                    decl_type dt);

extern IntrusivePtr<zeek::detail::Expr> add_and_assign_local(IntrusivePtr<ID> id,
                                               IntrusivePtr<zeek::detail::Expr> init,
                                               IntrusivePtr<Val> val = nullptr);

extern void add_type(ID* id, IntrusivePtr<BroType> t, attr_list* attr);

extern void begin_func(ID* id, const char* module_name, function_flavor flavor,
                       bool is_redef, IntrusivePtr<FuncType> t,
                       attr_list* attrs = nullptr);

extern void end_func(IntrusivePtr<zeek::detail::Stmt> body);

// Gather all IDs referenced inside a body that aren't part of a given scope.
extern id_list gather_outer_ids(Scope* scope, zeek::detail::Stmt* body);

extern Val* internal_val(const char* name);
extern Val* internal_const_val(const char* name); // internal error if not const
extern Val* opt_internal_val(const char* name);	// returns nil if not defined
extern double opt_internal_double(const char* name);
extern bro_int_t opt_internal_int(const char* name);
extern bro_uint_t opt_internal_unsigned(const char* name);
extern StringVal* opt_internal_string(const char* name);
extern TableVal* opt_internal_table(const char* name);	// nil if not defined
extern ListVal* internal_list_val(const char* name);
extern BroType* internal_type(const char* name);
extern Func* internal_func(const char* name);
extern EventHandlerPtr internal_handler(const char* name);

extern int signal_val;	// 0 if no signal pending
