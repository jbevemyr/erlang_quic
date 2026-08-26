%%% Optional sendmmsg(2) NIF wrapper. When the NIF is not built or
%%% fails to load, available/0 returns false and callers keep the
%%% per-batch sendmsg path.
-module(quic_mmsg).

-export([available/0, send_many/2]).

-on_load(load/0).

load() ->
    case nif_disabled() of
        true ->
            %% Opt-out: available/0 stays false and callers keep the
            %% per-batch sendmsg path.
            ok;
        false ->
            Path = filename:join(code:priv_dir(quic), "quic_mmsg_nif"),
            case erlang:load_nif(Path, 0) of
                ok ->
                    persistent_term:put({?MODULE, loaded}, true),
                    ok;
                {error, _} ->
                    ok
            end
    end.

%% Runtime opt-out for benchmarking and fault isolation, read once at
%% module load: QUIC_DISABLE_MMSG_NIF=1 disables this NIF alone,
%% QUIC_DISABLE_NIFS=1 disables every optional NIF.
nif_disabled() ->
    env_true("QUIC_DISABLE_MMSG_NIF") orelse env_true("QUIC_DISABLE_NIFS").

env_true(Var) ->
    case os:getenv(Var) of
        "1" -> true;
        "true" -> true;
        _ -> false
    end.

-spec available() -> boolean().
available() ->
    persistent_term:get({?MODULE, loaded}, false).

%% Entries: [{Addr, Port, PayloadIovec, GsoSegSize}], SegSize 0 = none.
%% PayloadIovec must be an erlang:iolist_to_iovec/1 result; the NIF
%% sends it gather-style without flattening.
-spec send_many(integer(), [{inet:ip_address(), inet:port_number(), [binary()], non_neg_integer()}]) ->
    {ok, non_neg_integer()} | {error, term()}.
send_many(_Fd, _Entries) ->
    erlang:nif_error(not_loaded).
