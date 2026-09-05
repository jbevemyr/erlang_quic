%% The AEAD path uses a reusable cipher context when the running OTP
%% has one (crypto_one_time_aead_init/4, OTP 28+) and the one-shot API
%% otherwise. Both must produce identical bytes and identical failures,
%% since a connection cannot know which path its peer took.
%%
%% The context cache lives in the calling process dictionary, so a test
%% forces the fallback by setting the cached capability flag to false.
-module(quic_aead_context_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TAG_LEN, 16).

ciphers() -> [aes_128_gcm, aes_256_gcm, chacha20_poly1305].

keylen(aes_128_gcm) -> 16;
keylen(aes_256_gcm) -> 32;
keylen(chacha20_poly1305) -> 32.

%% Both helpers pin the NIF off: it sits above the OTP path and would
%% answer first, leaving the two OTP paths under test unreached.
with_context() ->
    erlang:erase(),
    erlang:put(qc_nif, false),
    ok.

with_fallback() ->
    erlang:erase(),
    erlang:put(qc_nif, false),
    erlang:put(aead_ctx_api, false),
    ok.

has_context_api() ->
    lists:member({crypto_one_time_aead_init, 4}, crypto:module_info(exports)).

%% Both paths seal to the same bytes, for every cipher and a spread of
%% payload sizes including the empty one.
seal_agrees_across_paths_test() ->
    lists:foreach(
        fun(Cipher) ->
            Key = crypto:strong_rand_bytes(keylen(Cipher)),
            IV = crypto:strong_rand_bytes(12),
            lists:foreach(
                fun(Size) ->
                    P = crypto:strong_rand_bytes(Size),
                    AAD = crypto:strong_rand_bytes(20),
                    with_context(),
                    A = quic_aead:encrypt(Key, IV, 42, AAD, P, Cipher),
                    with_fallback(),
                    B = quic_aead:encrypt(Key, IV, 42, AAD, P, Cipher),
                    ?assertEqual({Cipher, Size, B}, {Cipher, Size, A})
                end,
                [0, 1, 16, 100, 1200]
            )
        end,
        ciphers()
    ),
    erlang:erase().

%% Sealed on one path, opened on the other, in both directions.
open_agrees_across_paths_test() ->
    lists:foreach(
        fun(Cipher) ->
            Key = crypto:strong_rand_bytes(keylen(Cipher)),
            IV = crypto:strong_rand_bytes(12),
            P = crypto:strong_rand_bytes(300),
            AAD = crypto:strong_rand_bytes(20),
            with_context(),
            Sealed = quic_aead:encrypt(Key, IV, 7, AAD, P, Cipher),
            ?assertEqual({ok, P}, quic_aead:decrypt(Key, IV, 7, AAD, Sealed, Cipher)),
            with_fallback(),
            ?assertEqual({ok, P}, quic_aead:decrypt(Key, IV, 7, AAD, Sealed, Cipher))
        end,
        ciphers()
    ),
    erlang:erase().

%% A corrupted tag is rejected the same way on both paths, and the
%% context survives the failure and still opens the next packet.
bad_tag_rejected_on_both_paths_test() ->
    lists:foreach(
        fun(Cipher) ->
            Key = crypto:strong_rand_bytes(keylen(Cipher)),
            IV = crypto:strong_rand_bytes(12),
            P = crypto:strong_rand_bytes(200),
            AAD = crypto:strong_rand_bytes(20),
            Sealed = quic_aead:encrypt(Key, IV, 3, AAD, P, Cipher),
            Len = byte_size(Sealed) - ?TAG_LEN,
            <<Body:Len/binary, _/binary>> = Sealed,
            Corrupt = <<Body/binary, 0:(?TAG_LEN * 8)>>,
            lists:foreach(
                fun(Setup) ->
                    Setup(),
                    ?assertEqual(
                        {error, bad_tag},
                        quic_aead:decrypt(Key, IV, 3, AAD, Corrupt, Cipher)
                    ),
                    %% Not poisoned by the failure.
                    ?assertEqual(
                        {ok, P}, quic_aead:decrypt(Key, IV, 3, AAD, Sealed, Cipher)
                    )
                end,
                [fun with_context/0, fun with_fallback/0]
            )
        end,
        ciphers()
    ),
    erlang:erase().

%% Input too short to hold a tag is an authentication failure, not a
%% crash. The context API raises on it and the hand split fails its
%% binary match, so both paths have to be guarded.
short_input_is_rejected_not_raised_test() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    lists:foreach(
        fun(Setup) ->
            lists:foreach(
                fun(Size) ->
                    Setup(),
                    Short = crypto:strong_rand_bytes(Size),
                    ?assertEqual(
                        {Size, {error, bad_tag}},
                        {Size, quic_aead:decrypt(Key, IV, 1, <<"aad">>, Short, aes_128_gcm)}
                    )
                end,
                [0, 1, 15]
            )
        end,
        [fun with_context/0, fun with_fallback/0]
    ),
    erlang:erase().

%% Two keys per direction stay live across a key update; a third drops
%% the pair rather than letting the cache grow for the life of the
%% connection.
context_cache_is_bounded_test() ->
    case has_context_api() of
        false ->
            ok;
        true ->
            with_context(),
            IV = crypto:strong_rand_bytes(12),
            lists:foreach(
                fun(_) ->
                    Key = crypto:strong_rand_bytes(16),
                    _ = quic_aead:encrypt(Key, IV, 1, <<>>, <<"payload">>, aes_128_gcm)
                end,
                lists:seq(1, 100)
            ),
            Cached = [M || {{aead_ctx, _, _}, M} <- erlang:get()],
            ?assert(lists:all(fun(M) -> map_size(M) =< 2 end, Cached)),
            erlang:erase()
    end.

%% Reusing one key must still hit the cache: bounding it must not turn
%% into building a context per packet.
repeated_key_is_cached_test() ->
    case has_context_api() of
        false ->
            ok;
        true ->
            with_context(),
            Key = crypto:strong_rand_bytes(16),
            IV = crypto:strong_rand_bytes(12),
            lists:foreach(
                fun(_) ->
                    _ = quic_aead:encrypt(Key, IV, 1, <<>>, <<"payload">>, aes_128_gcm)
                end,
                lists:seq(1, 50)
            ),
            ?assertEqual(
                [1],
                [map_size(M) || {{aead_ctx, aes_128_gcm, true}, M} <- erlang:get()]
            ),
            erlang:erase()
    end.
