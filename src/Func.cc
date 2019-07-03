// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <sys/resource.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include <sys/param.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>

#include <algorithm>

#include <broker/error.hh>

#include "Base64.h"
#include "Stmt.h"
#include "Scope.h"
#include "Net.h"
#include "NetVar.h"
#include "File.h"
#include "Func.h"
#include "Frame.h"
#include "Var.h"
#include "analyzer/protocol/login/Login.h"
#include "Sessions.h"
#include "RE.h"
#include "Event.h"
#include "Traverse.h"
#include "Reporter.h"
#include "plugin/Manager.h"

extern	RETSIGTYPE sig_handler(int signo);

vector<CallInfo> call_stack;
bool did_builtin_init = false;

vector<Func*> Func::unique_ids;
static const std::pair<bool, Val*> empty_hook_result(false, NULL);

std::string render_call_stack()
	{
	std::string rval;
	int lvl = 0;

	if ( ! call_stack.empty() )
		rval += "| ";

	for ( auto it = call_stack.rbegin(); it != call_stack.rend(); ++it )
		{
		if ( lvl > 0 )
			rval += " | ";

		auto& ci = *it;
		auto name = ci.func->Name();
		std::string arg_desc;

		if ( ci.args )
			{
			for ( const auto& arg : *ci.args )
				{
				ODesc d;
				d.SetShort();
				arg->Describe(&d);

				if ( ! arg_desc.empty() )
					arg_desc += ", ";

				arg_desc += d.Description();
				}
			}

		rval += fmt("#%d %s(%s)", lvl, name, arg_desc.data());

		if ( ci.call )
			{
			auto loc = ci.call->GetLocationInfo();
			rval += fmt(" at %s:%d", loc->filename, loc->first_line);
			}

		++lvl;
		}

	if ( ! call_stack.empty() )
		rval += " |";

	return rval;
	}

FuncOverload::FuncOverload()
: func(), type()
	{
	}

FuncOverload::FuncOverload(Func* arg_func, FuncType* arg_type)
: func(arg_func), type(arg_type)
	{
	::Ref(type);
	}

FuncOverload::~FuncOverload()
	{
	Unref(type);
	}

const char* FuncOverload::Name() const
	{
	return func->Name();
	}

function_flavor FuncOverload::Flavor() const
	{
	return func->Flavor();
	}

Func::Func(Kind arg_kind, std::string arg_name)
: kind(arg_kind), name(std::move(arg_name)), unique_id(unique_ids.size())
	{
	unique_ids.emplace_back(this);
	}

Func::~Func()
	{
	for ( auto& o : overloads )
		delete o;
	}

Val* Func::Call(val_list* args, Frame* parent) const
	{
	if ( overloads.size() == 1 )
		// Note: va_args BIFs would be one case that relies on taking this
		// shortcut not just as a performance optimization.  Should be safe
		// because we can't overload such va_args functions.
		return overloads[0]->Call(args, parent);

	for ( auto i = 0u; i < overloads.size(); ++i )
		{
		auto& o = overloads[i];
		// TODO: each overload value is storing the full FuncType (which
		// has all the overload types), which is probably excessive and/or
		// can be simplified.
		auto otype = o->GetType()->GetOverload(i);
		auto oargs = otype->arg_types->Types();

		if ( oargs->length() != args->length() )
			continue;

		auto args_match = true;

		for ( auto i = 0; i < oargs->length(); ++i )
			{
			if ( ! same_type((*oargs)[i], (*args)[i]->Type()) )
				{
				args_match = false;
				break;
				}
			}

		if ( args_match )
			return o->Call(args, parent);
		}

	reporter->PushLocation(GetLocationInfo());
	reporter->FatalError("Invalid function call for %s: no matching overload", Name());
	return nullptr;
	}

void Func::AddOverload(FuncOverload* fo)
	{
	overloads.emplace_back(fo);
	}

Func* Func::DoClone()
	{
	// By default, ok just to return a reference. Func does not have any state
	// that is different across instances.
	return this;
	}

Scope* Func::GetScope() const
	{
	assert(overloads.size() == 1);
	assert(dynamic_cast<const BroFunc*>(overloads[0]));
	return dynamic_cast<const BroFunc*>(overloads[0])->GetScope();
	}

const vector<FuncBody>& Func::GetBodies() const
	{
	assert(overloads.size() == 1);
	assert(dynamic_cast<const BroFunc*>(overloads[0]));
	return dynamic_cast<const BroFunc*>(overloads[0])->GetBodies();
	}

bool Func::HasBodies() const
	{
	assert(overloads.size() == 1);
	assert(dynamic_cast<const BroFunc*>(overloads[0]));
	return dynamic_cast<const BroFunc*>(overloads[0])->GetBodies().size();
	}

void Func::Describe(ODesc* d) const
	{
	// TODO: print all overloads ?
	assert(overloads.size() == 1);
	overloads[0]->Describe(d);
	}

void Func::DescribeDebug(ODesc* d, const val_list* args) const
	{
	// TODO: print all overloads ?
	d->Add(Name());

	RecordType* func_args = FType()->Args();

	if ( args )
		{
		d->Add("(");

		for ( int i = 0; i < args->length(); ++i )
			{
			// Handle varargs case (more args than formals).
			if ( i >= func_args->NumFields() )
				{
				d->Add("vararg");
				d->Add(i - func_args->NumFields());
				}
			else
				d->Add(func_args->FieldName(i));

			d->Add(" = '");
			(*args)[i]->Describe(d);

			if ( i < args->length() - 1 )
				d->Add("', ");
			else
				d->Add("'");
			}

		d->Add(")");
		}
	}

TraversalCode Func::Traverse(TraversalCallback* cb) const
	{
	// TODO: traverse all overloads
	// FIXME: Make a fake scope for builtins?
	Scope* old_scope = cb->current_scope;
	cb->current_scope = GetScope();

	TraversalCode tc = cb->PreFunction(this);
	HANDLE_TC_STMT_PRE(tc);

	// FIXME: Traverse arguments to builtin functions, too.
	if ( kind == BRO_FUNC && GetScope() )
		{
		tc = GetScope()->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);

		for ( unsigned int i = 0; i < GetBodies().size(); ++i )
			{
			tc = GetBodies()[i].stmts->Traverse(cb);
			HANDLE_TC_STMT_PRE(tc);
			}
		}

	tc = cb->PostFunction(this);

	cb->current_scope = old_scope;
	HANDLE_TC_STMT_POST(tc);
	}

void Func::CopyStateInto(Func* other) const
	{
	std::for_each(bodies.begin(), bodies.end(), [](const Body& b) { Ref(b.stmts); });

	other->bodies = bodies;
	other->scope = scope;
	other->kind = kind;

	Ref(type);
	other->type = type;

	other->name = name;
	other->unique_id = unique_id;
	}

// Helper function for handling result of plugin hook.
static std::pair<bool, Val*> HandlePluginResult(const FuncOverload* func, std::pair<bool, Val*> plugin_result, val_list* args, function_flavor flavor)
	{
	// Helper function factoring out this code from BroFunc:Call() for
	// better readability.

	if( ! plugin_result.first )
		{
		if( plugin_result.second )
			reporter->InternalError("plugin set processed flag to false but actually returned a value");

		// The plugin result hasn't been processed yet (read: fall
		// into ::Call method).
		return plugin_result;
		}

	switch ( flavor ) {
	case FUNC_FLAVOR_EVENT:
		if( plugin_result.second )
			reporter->InternalError("plugin returned non-void result for event %s", func->Name());

		break;

	case FUNC_FLAVOR_HOOK:
		if ( plugin_result.second->Type()->Tag() != TYPE_BOOL )
			reporter->InternalError("plugin returned non-bool for hook %s", func->Name());

		break;

	case FUNC_FLAVOR_FUNCTION:
		{
		BroType* yt = func->GetType()->YieldType();

		if ( (! yt) || yt->Tag() == TYPE_VOID )
			{
			if( plugin_result.second )
				reporter->InternalError("plugin returned non-void result for void method %s", func->Name());
			}

		else if ( plugin_result.second && plugin_result.second->Type()->Tag() != yt->Tag() && yt->Tag() != TYPE_ANY)
			{
			reporter->InternalError("plugin returned wrong type (got %d, expecting %d) for %s",
						plugin_result.second->Type()->Tag(), yt->Tag(), func->Name());
			}

		break;
		}
	}

	for ( const auto& arg : *args )
		Unref(arg);

	return plugin_result;
	}

BroFunc::BroFunc(Func* f, BroType* arg_type, Stmt* arg_body,
                 id_list* aggr_inits, int arg_frame_size, int priority,
                 Scope* arg_scope)
: FuncOverload(f, arg_type->AsFuncType())
	{
	scope = arg_scope;
	frame_size = arg_frame_size;

	if ( arg_body )
		{
		FuncBody b;
		b.stmts = AddInits(arg_body, aggr_inits);
		b.priority = priority;
		bodies.push_back(b);
		}
	}

BroFunc::~BroFunc()
	{
	std::for_each(bodies.begin(), bodies.end(),
		[](Body& b) { Unref(b.stmts); });
	Unref(closure);
	}

int BroFunc::IsPure() const
	{
	return std::all_of(bodies.begin(), bodies.end(),
		[](const Body& b) { return b.stmts->IsPure(); });
	}

Val* BroFunc::Call(val_list* args, Frame* parent) const
	{
#ifdef PROFILE_BRO_FUNCTIONS
	DEBUG_MSG("Function: %s\n", Name());
#endif

	SegmentProfiler(segment_logger, func->GetLocationInfo());

	if ( sample_logger )
		sample_logger->FunctionSeen(func);

	std::pair<bool, Val*> plugin_result = PLUGIN_HOOK_WITH_RESULT(HOOK_CALL_FUNCTION, HookCallFunction(GetFunc(), parent, args), empty_hook_result);

	plugin_result = HandlePluginResult(this, plugin_result, args, Flavor());

	if( plugin_result.first )
		{
		Val *result = plugin_result.second;
		return result;
		}

	if ( bodies.empty() )
		{
		// Can only happen for events and hooks.
		assert(Flavor() == FUNC_FLAVOR_EVENT || Flavor() == FUNC_FLAVOR_HOOK);
		for ( const auto& arg : *args )
			Unref(arg);

		return Flavor() == FUNC_FLAVOR_HOOK ? val_mgr->GetTrue() : 0;
		}

	Frame* f = new Frame(frame_size, this, args);

	if ( closure )
		f->CaptureClosure(closure, outer_ids);

	// Hand down any trigger.
	if ( parent )
		{
		f->SetTrigger(parent->GetTrigger());
		f->SetCall(parent->GetCall());
		}

	g_frame_stack.push_back(f);	// used for backtracing
	const CallExpr* call_expr = parent ? parent->GetCall() : nullptr;
	call_stack.emplace_back(CallInfo{call_expr, this, args});

	if ( g_trace_state.DoTrace() )
		{
		ODesc d;
		GetFunc()->DescribeDebug(&d, args);

		g_trace_state.LogTrace("%s called: %s\n",
			type->FlavorString().c_str(), d.Description());
		}

	stmt_flow_type flow = FLOW_NEXT;
	Val* result = 0;

	for ( const auto& body : bodies )
		{
		if ( sample_logger )
			sample_logger->LocationSeen(
				body.stmts->GetLocationInfo());

		Unref(result);

		// Fill in the rest of the frame with the function's arguments.
		loop_over_list(*args, j)
			{
			Val* arg = (*args)[j];

			if ( f->NthElement(j) != arg )
				{
				// Either not yet set, or somebody reassigned the frame slot.
				Ref(arg);
				f->SetElement(j, arg);
				}
			}

		f->Reset(args->length());

		try
			{
			result = body.stmts->Exec(f, flow);
			}

		catch ( InterpreterException& e )
			{
			// Already reported, but now determine whether to unwind further.
			if ( Flavor() == FUNC_FLAVOR_FUNCTION )
				{
				Unref(f);
				// Result not set b/c exception was thrown
				throw;
				}

			// Continue exec'ing remaining bodies of hooks/events.
			continue;
			}

		if ( f->HasDelayed() )
			{
			assert(! result);
			assert(parent);
			parent->SetDelayed();
			break;
			}

		if ( Flavor() == FUNC_FLAVOR_HOOK )
			{
			// Ignore any return values of hook bodies, final return value
			// depends on whether a body returns as a result of break statement.
			Unref(result);
			result = 0;

			if ( flow == FLOW_BREAK )
				{
				// Short-circuit execution of remaining hook handler bodies.
				result = val_mgr->GetFalse();
				break;
				}
			}
		}

	call_stack.pop_back();

	// We have an extra Ref for each argument (so that they don't get
	// deleted between bodies), release that.
	for ( const auto& arg : *args )
		Unref(arg);

	if ( Flavor() == FUNC_FLAVOR_HOOK )
		{
		if ( ! result )
			result = val_mgr->GetTrue();
		}

	// Warn if the function returns something, but we returned from
	// the function without an explicit return, or without a value.
	else if ( type->YieldType() && type->YieldType()->Tag() != TYPE_VOID &&
		 (flow != FLOW_RETURN /* we fell off the end */ ||
		  ! result /* explicit return with no result */) &&
		 ! f->HasDelayed() )
		reporter->Warning("non-void function returning without a value: %s",
				  Name());

	if ( result && g_trace_state.DoTrace() )
		{
		ODesc d;
		result->Describe(&d);

		g_trace_state.LogTrace("Function return: %s\n", d.Description());
		}

	g_frame_stack.pop_back();

	Unref(f);

	return result;
	}

void BroFunc::AddBody(Stmt* new_body, id_list* new_inits, int new_frame_size,
                      int priority, Scope* scope)
	{
	if ( new_frame_size > frame_size )
		frame_size = new_frame_size;

	new_body = AddInits(new_body, new_inits);

	if ( func->Flavor() == FUNC_FLAVOR_FUNCTION )
		{
		// For functions, we replace the old body with the new one.
		assert(bodies.size() <= 1);
		for ( const auto& body : bodies )
			Unref(body.stmts);
		bodies.clear();
		}

	FuncBody b;
	b.stmts = new_body;
	b.priority = priority;

	bodies.push_back(b);
	sort(bodies.begin(), bodies.end());
	}

void BroFunc::AddClosure(id_list ids, Frame* f)
	{
	if ( ! f )
		return;

	SetOuterIDs(std::move(ids));
	SetClosureFrame(f);
	}

void BroFunc::SetClosureFrame(Frame* f)
	{
	if ( closure )
		reporter->InternalError("Tried to override closure for BroFunc %s.",
					Name());

	closure = f;
	Ref(closure);
	}

bool BroFunc::UpdateClosure(const broker::vector& data)
	{
	auto result = Frame::Unserialize(data);
	if ( ! result.first )
		return false;

	Frame* new_closure = result.second;
	if ( new_closure )
		new_closure->SetFunction(this);

	if ( closure )
		Unref(closure);

	closure = new_closure;

	return true;
	}


Func* BroFunc::DoClone()
	{
	// BroFunc could hold a closure. In this case a clone of it must
	// store a copy of this closure.
	BroFunc* other = new BroFunc();

	CopyStateInto(other);

	other->frame_size = frame_size;
	other->closure = closure ? closure->SelectiveClone(outer_ids) : nullptr;
	other->outer_ids = outer_ids;

	return other;
	}

broker::expected<broker::data> BroFunc::SerializeClosure() const
	{
	return Frame::Serialize(closure, outer_ids);
	}

void BroFunc::Describe(ODesc* d) const
	{
	d->Add(Name());

	d->NL();
	d->AddCount(frame_size);
	for ( unsigned int i = 0; i < bodies.size(); ++i )
		{
		bodies[i].stmts->AccessStats(d);
		bodies[i].stmts->Describe(d);
		}
	}

Stmt* BroFunc::AddInits(Stmt* body, id_list* inits)
	{
	if ( ! inits || inits->length() == 0 )
		return body;

	StmtList* stmt_series = new StmtList;
	stmt_series->Stmts().push_back(new InitStmt(inits));
	stmt_series->Stmts().push_back(body);

	return stmt_series;
	}

BuiltinFunc::BuiltinFunc(built_in_func arg_func, const char* arg_name,
			int arg_is_pure)
: FuncOverload()
	{
	internal_func = arg_func;
	is_pure = arg_is_pure;

	auto name = make_full_var_name(GLOBAL_MODULE_NAME, arg_name);

	ID* id = lookup_ID(name.data(), GLOBAL_MODULE_NAME, false);

	if ( ! id )
		reporter->InternalError("built-in function %s missing", name.data());

	// TODO: support overloads
	if ( id->HasVal() )
		reporter->InternalError("built-in function %s multiply defined", name.data());

	auto f = new Func(Func::BUILTIN_FUNC, std::move(name));
	func = f;
	type = id->Type()->Ref()->AsFuncType();

	f->AddOverload(this);

	id->SetVal(new Val(f));
	Unref(id);
	}

int BuiltinFunc::IsPure() const
	{
	return is_pure;
	}

Val* BuiltinFunc::Call(val_list* args, Frame* parent) const
	{
#ifdef PROFILE_BRO_FUNCTIONS
	DEBUG_MSG("Function: %s\n", Name());
#endif
	SegmentProfiler(segment_logger, Name());

	if ( sample_logger )
		sample_logger->FunctionSeen(func);

	std::pair<bool, Val*> plugin_result = PLUGIN_HOOK_WITH_RESULT(HOOK_CALL_FUNCTION, HookCallFunction(GetFunc(), parent, args), empty_hook_result);

	plugin_result = HandlePluginResult(this, plugin_result, args, FUNC_FLAVOR_FUNCTION);

	if ( plugin_result.first )
		{
		Val *result = plugin_result.second;
		return result;
		}

	if ( g_trace_state.DoTrace() )
		{
		ODesc d;
		GetFunc()->DescribeDebug(&d, args);

		g_trace_state.LogTrace("\tBuiltin Function called: %s\n", d.Description());
		}

	const CallExpr* call_expr = parent ? parent->GetCall() : nullptr;
	call_stack.emplace_back(CallInfo{call_expr, this, args});
	Val* result = internal_func(parent, args);
	call_stack.pop_back();

	for ( const auto& arg : *args )
		Unref(arg);

	// Don't Unref() args, that's the caller's responsibility.
	if ( result && g_trace_state.DoTrace() )
		{
		ODesc d;
		result->Describe(&d);

		g_trace_state.LogTrace("\tFunction return: %s\n", d.Description());
		}

	return result;
	}

void BuiltinFunc::Describe(ODesc* d) const
	{
	d->Add(Name());
	d->AddCount(is_pure);
	}

void builtin_error(const char* msg, BroObj* arg)
	{
	auto emit = [=](const CallExpr* ce)
		{
		if ( ce )
			ce->Error(msg, arg);
		else
			reporter->Error(msg, arg);
		};


	if ( call_stack.empty() )
		{
		emit(nullptr);
		return;
		}

	auto last_call = call_stack.back();

	if ( call_stack.size() < 2 )
		{
		// Don't need to check for wrapper function like "<module>::__<func>"
		emit(last_call.call);
		return;
		}

	auto starts_with_double_underscore = [](const std::string& name) -> bool
		{ return name.size() > 2 && name[0] == '_' && name[1] == '_'; };
	std::string last_func = last_call.func->Name();

	auto pos = last_func.find_first_of("::");
	std::string wrapper_func;

	if ( pos == std::string::npos )
		{
		if ( ! starts_with_double_underscore(last_func) )
			{
			emit(last_call.call);
			return;
			}

		wrapper_func = last_func.substr(2);
		}
	else
		{
		auto module_name = last_func.substr(0, pos);
		auto func_name = last_func.substr(pos + 2);

		if ( ! starts_with_double_underscore(func_name) )
			{
			emit(last_call.call);
			return;
			}

		wrapper_func = module_name + "::" + func_name.substr(2);
		}

	auto parent_call = call_stack[call_stack.size() - 2];
	auto parent_func = parent_call.func->Name();

	if ( wrapper_func == parent_func )
		emit(parent_call.call);
	else
		emit(last_call.call);
	}

#include "zeek.bif.func_h"
#include "stats.bif.func_h"
#include "reporter.bif.func_h"
#include "strings.bif.func_h"
#include "option.bif.func_h"

#include "zeek.bif.func_def"
#include "stats.bif.func_def"
#include "reporter.bif.func_def"
#include "strings.bif.func_def"
#include "option.bif.func_def"

#include "__all__.bif.cc" // Autogenerated for compiling in the bif_target() code.
#include "__all__.bif.register.cc" // Autogenerated for compiling in the bif_target() code.

void init_builtin_funcs()
	{
	ProcStats = internal_type("ProcStats")->AsRecordType();
	NetStats = internal_type("NetStats")->AsRecordType();
	MatcherStats = internal_type("MatcherStats")->AsRecordType();
	ConnStats = internal_type("ConnStats")->AsRecordType();
	ReassemblerStats = internal_type("ReassemblerStats")->AsRecordType();
	DNSStats = internal_type("DNSStats")->AsRecordType();
	GapStats = internal_type("GapStats")->AsRecordType();
	EventStats = internal_type("EventStats")->AsRecordType();
	TimerStats = internal_type("TimerStats")->AsRecordType();
	FileAnalysisStats = internal_type("FileAnalysisStats")->AsRecordType();
	ThreadStats = internal_type("ThreadStats")->AsRecordType();
	BrokerStats = internal_type("BrokerStats")->AsRecordType();
	ReporterStats = internal_type("ReporterStats")->AsRecordType();

	var_sizes = internal_type("var_sizes")->AsTableType();

#include "zeek.bif.func_init"
#include "stats.bif.func_init"
#include "reporter.bif.func_init"
#include "strings.bif.func_init"
#include "option.bif.func_init"

	did_builtin_init = true;
	}

void init_builtin_funcs_subdirs()
{
	#include "__all__.bif.init.cc" // Autogenerated for compiling in the bif_target() code.
}

bool check_built_in_call(BuiltinFunc* f, CallExpr* call)
	{
	if ( f->InternalFunc() != BifFunc::bro_fmt )
		return true;

	const expr_list& args = call->Args()->Exprs();
	if ( args.length() == 0 )
		{
		// Empty calls are allowed, since you can't just
		// use "print;" to get a blank line.
		return true;
		}

	const Expr* fmt_str_arg = args[0];
	if ( fmt_str_arg->Type()->Tag() != TYPE_STRING )
		{
		call->Error("first argument to fmt() needs to be a format string");
		return false;
		}

	Val* fmt_str_val = fmt_str_arg->Eval(0);

	if ( fmt_str_val )
		{
		const char* fmt_str = fmt_str_val->AsStringVal()->CheckString();

		int num_fmt = 0;
		while ( *fmt_str )
			{
			if ( *(fmt_str++) != '%' )
				continue;

			if ( ! *fmt_str )
				{
				call->Error("format string ends with bare '%'");
				return false;
				}

			if ( *(fmt_str++) != '%' )
				// Not a "%%" escape.
				++num_fmt;
			}

		if ( args.length() != num_fmt + 1 )
			{
			call->Error("mismatch between format string to fmt() and number of arguments passed");
			return false;
			}
		}

	return true;
	}
