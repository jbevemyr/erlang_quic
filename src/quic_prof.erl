%%% File-triggered in-node profiler for deployments where the node
%%% cannot be reached over distribution (containers with custom epmd /
%%% TLS dist). Enabled by the QUIC_PROF_DIR environment variable; then
%%% creating <dir>/trigger runs a profiling round and writes:
%%%
%%%   <dir>/msacc.txt  - 10 s microstate accounting (emulator vs port
%%%                      vs GC vs sleep split per thread type)
%%%   <dir>/eprof.txt  - 10 s eprof over all processes, sorted
%%%   <dir>/procs.txt  - top processes by reductions over the window
%%%   <dir>/done       - marker written last
%%%
%%% One round at a time; the trigger file is removed when the round
%%% starts. Overhead when idle: one file existence check per second.
-module(quic_prof).

-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(POLL_MS, 1000).
-define(SAMPLE_MS, 10000).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    case os:getenv("QUIC_PROF_DIR") of
        false ->
            ignore;
        Dir ->
            _ = filelib:ensure_dir(filename:join(Dir, "x")),
            {ok, Dir, ?POLL_MS}
    end.

handle_call(_Req, _From, Dir) ->
    {reply, ok, Dir, ?POLL_MS}.

handle_cast(_Msg, Dir) ->
    {noreply, Dir, ?POLL_MS}.

handle_info(timeout, Dir) ->
    Trigger = filename:join(Dir, "trigger"),
    case filelib:is_file(Trigger) of
        true ->
            _ = file:delete(Trigger),
            _ = file:delete(filename:join(Dir, "done")),
            try
                run_round(Dir)
            catch
                C:E:St ->
                    _ = file:write_file(
                        filename:join(Dir, "error.txt"),
                        io_lib:format("~p:~p~n~p~n", [C, E, St])
                    )
            end,
            _ = file:write_file(filename:join(Dir, "done"), <<"ok\n">>);
        false ->
            ok
    end,
    {noreply, Dir, ?POLL_MS};
handle_info(_Info, Dir) ->
    {noreply, Dir, ?POLL_MS}.

run_round(Dir) ->
    %% Reductions snapshot for the top-process list.
    Before = [
        {P, element(2, I)}
     || P <- erlang:processes(),
        (I = erlang:process_info(P, reductions)) =/= undefined
    ],

    %% msacc window.
    ok = msacc_to_file(filename:join(Dir, "msacc.txt")),

    %% eprof window over everything but eprof itself.
    Procs = erlang:processes() -- [whereis(eprof)],
    profiling = eprof:start_profiling(Procs),
    timer:sleep(?SAMPLE_MS),
    _ = eprof:stop_profiling(),
    ok = eprof:log(filename:join(Dir, "eprof.txt")),
    _ = eprof:analyze(total),
    _ = eprof:stop(),

    %% Reductions delta.
    Lines = lists:filtermap(
        fun({P, R0}) ->
            case erlang:process_info(P, [reductions, registered_name, current_function]) of
                undefined ->
                    false;
                [{reductions, R1}, {registered_name, N}, {current_function, C}] ->
                    {true, {R1 - R0, P, N, C}}
            end
        end,
        Before
    ),
    Top = lists:sublist(lists:reverse(lists:sort(Lines)), 20),
    ok = file:write_file(
        filename:join(Dir, "procs.txt"),
        [io_lib:format("~12b ~w ~w ~w~n", [D, P, N, C]) || {D, P, N, C} <- Top]
    ).

msacc_to_file(Path) ->
    true = msacc:start(?SAMPLE_MS),
    {ok, F} = file:open(Path, [write]),
    try
        msacc:print(F, msacc:stats(), #{})
    after
        _ = file:close(F),
        _ = msacc:stop()
    end,
    ok.
