%% The NIF context cache lives in the connection process dictionary.
%% Two properties matter beyond "it caches": it must not grow without
%% bound as key updates derive fresh keys, and a context that cannot be
%% created must fall back to the OTP crypto path rather than raise,
%% since the NIF is meant to be optional.
-module(quic_aead_ctx_cache_tests).

-include_lib("eunit/include/eunit.hrl").

-define(IV, <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>).

with_nif(Fun) ->
    case quic_crypto_nif:is_loaded() of
        true -> Fun();
        false -> ok
    end.

clear() ->
    [erlang:erase(K) || {K, _} <- erlang:get()],
    ok.

cached_ctx_count() ->
    length([K || {K, _} <- erlang:get(), is_tuple(K), element(1, K) =/= qc_ctx_live]).

%% Every distinct key would otherwise leave a live EVP context behind.
%% A key update derives fresh keys, so this is the shape of a
%% long-lived bulk connection.
cache_stays_bounded_across_key_updates_test() ->
    with_nif(fun() ->
        clear(),
        lists:foreach(
            fun(_) ->
                Key = crypto:strong_rand_bytes(16),
                _ = quic_aead_ctx:aead_encrypt(aes_128_gcm, Key, ?IV, <<"payload">>, <<>>),
                %% Ciphertext||Tag: long enough to hold a tag so the
                %% decrypt context is actually built.
                _ = quic_aead_ctx:aead_decrypt(
                    aes_128_gcm, Key, ?IV, <<0:(23 * 8)>>, <<>>
                )
            end,
            lists:seq(1, 200)
        ),
        Live = cached_ctx_count(),
        ?assert(Live =< 6),
        clear()
    end).

%% Reusing one key must still hit the cache: bounding it must not turn
%% the accelerator into a per-packet context builder.
repeated_key_is_cached_test() ->
    with_nif(fun() ->
        clear(),
        Key = crypto:strong_rand_bytes(16),
        lists:foreach(
            fun(_) ->
                _ = quic_aead_ctx:aead_encrypt(aes_128_gcm, Key, ?IV, <<"payload">>, <<>>)
            end,
            lists:seq(1, 50)
        ),
        ?assertEqual(1, cached_ctx_count()),
        clear()
    end).

%% A key the NIF cannot build a context for (wrong length for the
%% cipher) must produce the same answer as the pure-Erlang path, not a
%% crash. crypto raises on the bad key too, so both sides agree by
%% raising the same class rather than one dying on a badmatch inside
%% the cache.
unbuildable_context_does_not_badmatch_test() ->
    with_nif(fun() ->
        clear(),
        Short = <<0:64>>,
        Got = attempt(fun() ->
            quic_aead_ctx:aead_encrypt(aes_128_gcm, Short, ?IV, <<"p">>, <<>>)
        end),
        Ref = attempt(fun() ->
            crypto:crypto_one_time_aead(aes_128_gcm, Short, ?IV, <<"p">>, <<>>, 16, true)
        end),
        %% Same outcome as the pure path, and in particular never a
        %% badmatch on {ok, Ctx} from inside the cache.
        ?assertEqual(Ref, Got),
        clear()
    end).

%% Reduce an outcome to something comparable across the two paths:
%% either both return a value or both raise the same class and reason.
attempt(Fun) ->
    try
        {ok, Fun()}
    catch
        Class:Reason -> {raised, Class, Reason}
    end.
