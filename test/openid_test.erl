-module(openid_test).
-include_lib("eunit/include/eunit.hrl").
-include("openid.hrl").

setup() ->
    [ application:start(X) || X <- [ crypto, public_key, ssl, sasl, inets ] ].

discover2_test_() ->
    Cases = [{"https://www.google.com/accounts/o8/id",
	      #openid_authreq{opURLs = ["https://www.google.com/accounts/o8/ud"],
			      version = {2,0},
			      claimedID = "http://specs.openid.net/auth/2.0/identifier_select",
			      localID = "http://specs.openid.net/auth/2.0/identifier_select",
			      assoc = none}},
	     {"http://flickr.com/exbrend",
	      #openid_authreq{opURLs = ["https://open.login.yahooapis.com/openid/op/auth"],
			      version = {2,0},
			      claimedID = "http://flickr.com/exbrend",
			      localID = "http://flickr.com/exbrend",
			      assoc = none}}
	    ],
    {setup, fun setup/0, [?_assertEqual(Result, openid:discover(URL))
			  || {URL, Result} <- Cases ]}.

discover1_test_() ->
    Cases = [{"etrepum.livejournal.com",
	      #openid_authreq{opURLs = ["http://www.livejournal.com/openid/server.bml"],
			      version = {2,0},
			      claimedID = "http://etrepum.livejournal.com/data/yadis",
			      localID = "http://etrepum.livejournal.com/",
			      assoc = none}}
	    ],
    {setup, fun setup/0, [?_assertEqual(Result, openid:discover(URL))
			  || {URL, Result} <- Cases ]}.

