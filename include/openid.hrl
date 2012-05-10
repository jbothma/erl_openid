%%%-------------------------------------------------------------------
%%% File    : openid.hrl
%%% Author  : Brendon Hogger <brendonh@dev.brendonh.org>
%%% Description : OpenID-related record definitions
%%%
%%% Created : 18 Sep 2009 by Brendon Hogger <brendonh@dev.brendonh.org>
%%%-------------------------------------------------------------------

-define(GV(E, P), proplists:get_value(E, P)).
-define(GVD(E, P, D), proplists:get_value(E, P, D)).
-define(DBG(Term), io:format("~p: ~p~n", [self(), Term])).
-define(XRI_GCTX_SYMBOLS, [$=, $@, $+, $$, $!, $(]).

-type(url() :: string()).

-record(openid_xrdservice, {
          types :: [url()],
          uris :: [url()],
          localID :: none | string()
         }).

-record(openid_xrds, {
          origID :: string(),
          claimedID :: none | string(),
          canonicalID :: string(),
          isXRI :: boolean(),
          services :: [#openid_xrdservice{}]
         }).

-record(openid_assoc, {
          opURL :: url(),
          handle :: string(),
          created :: erlang:timestamp(),
          expiresIn :: integer(),
          servPublic :: binary(),
          mac :: binary()
         }).

-record(openid_authreq, {
          opURLs :: [url()],
          version :: {1,0} | {1, 1} | {2, 0},
          claimedID=none :: none | string(),
          localID=none :: none | string()
         }).
