%%% Optional sendmmsg(2) NIF wrapper. When the NIF is not built or
%%% fails to load, available/0 returns false and callers keep the
%%% per-batch sendmsg path.
-module(quic_mmsg).

-export([available/0, send_many/2]).

-on_load(load/0).

load() ->
    Path = filename:join(code:priv_dir(quic), "quic_mmsg_nif"),
    case erlang:load_nif(Path, 0) of
        ok ->
            persistent_term:put({?MODULE, loaded}, true),
            ok;
        {error, _} ->
            ok
    end.

-spec available() -> boolean().
available() ->
    persistent_term:get({?MODULE, loaded}, false).

%% Entries: [{Addr, Port, PayloadIolist, GsoSegSize}], SegSize 0 = none.
-spec send_many(integer(), [{inet:ip_address(), inet:port_number(), iodata(), non_neg_integer()}]) ->
    {ok, non_neg_integer()} | {error, term()}.
send_many(_Fd, _Entries) ->
    erlang:nif_error(not_loaded).
