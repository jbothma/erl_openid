-module(openid_http).
-export([get/1, post/3]).

-define(MAX_REDIRECTS, 5). %% too generous?

get(URL) ->
    get(URL, ?MAX_REDIRECTS).

get(URL, Redirects) ->
    ReqHeaders = [{"Accept", "application/xrds+xml;level=1, */*"},
                  {"Connection", "close"},
                  {"User-Agent", "Erlang/erl_openid"}],
    ResponseRaw = httpc:request(get, {URL, ReqHeaders},
                                [{autoredirect, false}],
                                []),
    Response = normalise_response(ResponseRaw),
    case Response of
        {ok, Rcode, RespHeaders, _Body}
          when Rcode > 300 andalso Rcode < 304 andalso Redirects > 0 ->
            case get_redirect_url(URL, RespHeaders) of
                undefined ->
                    Response;
                URL ->
                    Response;
                NewURL ->
                    get(NewURL, Redirects - 1)
            end;
        Response ->
            Response
    end.

post(URL, ContentType, Body) ->
    normalise_response(
      httpc:request(post, {URL, [], ContentType, Body}, [], [])).

get_redirect_url(OldURL, Headers) ->
    Location = proplists:get_value("location", Headers),
    case Location of
        "http://" ++ _ ->
            Location;
        "https://" ++ _ ->
            Location;
        "/" ++ _ ->
            {ok, {Protocol, _UserInfo, Host, Port,
                  _Path, _Query}} = http_uri:parse(OldURL),
            PortFrag = case {Protocol, Port} of
                           {http, 80} ->
                               "";
                           {https, 443} ->
                               "";
                           _ ->
                               ":" ++ integer_to_list(Port)
                       end,
            atom_to_list(Protocol) ++ "://" ++ Host ++ PortFrag ++ Location;
        _ ->
            undefined
    end.

normalise_response({ok, {{_HttpVer, RcodeInt, _Reason},
                         Headers,
                         Body}}) ->
    LowHeaders = [{string:to_lower(K), V} || {K, V} <- Headers],
    {ok, RcodeInt, LowHeaders, Body};
normalise_response(X) ->
    X.
