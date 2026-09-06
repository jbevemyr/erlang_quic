%%% -*- erlang -*-
%%%
%%% Pacing on sub-millisecond paths: the rate follows the microsecond
%%% RTT instead of flooring it at one millisecond.
%%%

-module(quic_pacing_rtt_tests).

-include_lib("eunit/include/eunit.hrl").

%% With the bucket drained, the wait for one large send is inversely
%% proportional to the pacing rate. A 300 µs RTT must pace about three
%% times faster than a 1 ms one; a 1 ms floor would make them equal.
lan_rtt_is_not_floored_at_a_millisecond_test() ->
    Cwnd = 12000,
    Delay = fun(RttUs) ->
        CC0 = quic_cc:new(#{algorithm => newreno, initial_window => Cwnd}),
        CC1 = quic_cc:update_pacing_rate(CC0, RttUs),
        {_, CC2} = quic_cc:get_pacing_tokens(CC1, 1 bsl 40),
        quic_cc:pacing_delay(CC2, 4 * 1048576)
    end,
    Fast = Delay(300),
    Slow = Delay(1000),
    ?assert(Fast > 0),
    ?assert(Slow > Fast),
    ?assert(abs(Slow - 3 * Fast) =< max(2, Slow div 10)).

%% The loss module reports the sample it measured, not a rounded one.
rtt_sample_keeps_microseconds_test() ->
    S0 = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(S0, 0, 1200, true, [], 1000000),
    {S2, _, _, _} = quic_loss:on_ack_received(S1, {ack, 0, 0, 0, []}, 1000300),
    ?assertEqual(300, quic_loss:latest_rtt_us(S2)),
    ?assertEqual(300, quic_loss:smoothed_rtt_us(S2)),
    ?assertEqual(0, quic_loss:smoothed_rtt(S2)),
    ?assert(quic_loss:get_pto(S2) > 0).
