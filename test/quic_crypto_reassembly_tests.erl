%%% CRYPTO reassembly of overlapping and duplicate retransmissions.
%%%
%%% RFC 9000 §13.3 lets a peer split or coalesce data it retransmits
%%% differently from the original send, so buffered CRYPTO chunks can
%%% overlap and can repeat data already consumed. Keying the buffer by
%%% exact offset left the straddling bytes unreachable and wedged the
%%% handshake, and left the consumed ones to accumulate against
%%% ?MAX_CRYPTO_BUFFER_BYTES until a healthy connection was closed.
-module(quic_crypto_reassembly_tests).

-include_lib("eunit/include/eunit.hrl").

chunk(Start, Len) ->
    <<<<(B rem 256)>> || B <- lists:seq(Start, Start + Len - 1)>>.

trim(Buffer, Offset) ->
    quic_connection:trim_reassembly_buffer(Buffer, Offset).

consumed_chunks_are_dropped_test() ->
    Buffer = #{0 => chunk(0, 100), 100 => chunk(100, 100)},
    ?assertEqual(#{}, trim(Buffer, 200)).

%% The wedge: the chunk holding the bytes we need starts before the
%% offset we are waiting for, so an exact lookup never finds it.
straddling_chunk_is_rekeyed_test() ->
    Buffer = #{100 => chunk(100, 500)},
    ?assertEqual(#{400 => chunk(400, 200)}, trim(Buffer, 400)).

mixed_consumed_and_straddling_test() ->
    Buffer = #{100 => chunk(100, 500), 300 => chunk(300, 100)},
    ?assertEqual(#{400 => chunk(400, 200)}, trim(Buffer, 400)).

%% Two chunks trimming to the same offset collapse to the longer one, so
%% a shorter retransmission cannot displace live data.
longer_chunk_wins_test() ->
    Buffer = #{100 => chunk(100, 500), 200 => chunk(200, 600)},
    ?assertEqual(#{300 => chunk(300, 500)}, trim(Buffer, 300)).

future_chunks_are_untouched_test() ->
    Buffer = #{800 => chunk(800, 100), 900 => chunk(900, 100)},
    ?assertEqual(Buffer, trim(Buffer, 800)).

gap_is_preserved_test() ->
    Buffer = #{0 => chunk(0, 100), 900 => chunk(900, 10)},
    ?assertEqual(#{900 => chunk(900, 10)}, trim(Buffer, 500)).

idempotent_test() ->
    Buffer = #{0 => chunk(0, 100), 50 => chunk(50, 300), 200 => chunk(200, 400)},
    Once = trim(Buffer, 120),
    ?assertEqual(Once, trim(Once, 120)).

empty_test() ->
    ?assertEqual(#{}, trim(#{}, 0)).
