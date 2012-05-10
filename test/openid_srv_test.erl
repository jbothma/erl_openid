-module(openid_srv_test).
-include_lib("eunit/include/eunit.hrl").
-include("openid.hrl").

prepare_test_() ->
    {setup, fun openid:start/0,
     {timeout, 5000,
      ?_test(
         begin
             {ok, Server} = gen_server:start(openid_srv, start_link, [test_server]),
             Result = (catch gen_server:call(Server, {prepare, "foo", "http://exbrend.livejournal.com", true})),
             ?_assertEqual(ok, element(1, Result))
         end)
     }
    }.
