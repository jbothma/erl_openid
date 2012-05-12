%%%-------------------------------------------------------------------
%%% File    : openid.erl
%%% Author  : Brendon Hogger <brendonh@dev.brendonh.org>
%%% Description :
%%%
%%% Created : 18 Sep 2009 by Brendon Hogger <brendonh@dev.brendonh.org>
%%%-------------------------------------------------------------------
-module(openid).

-export([discover/1, associate/1, authentication_url/4, authentication_url/5,
         start/0, verify/3, ax/1, verify_ax/2, assoc_handle/1]).

-include("openid.hrl").
-define(APP, openid).

start() ->
    application:load(?APP),
    {ok, Deps} = application:get_key(?APP, applications),
    lists:foreach(fun application:start/1, Deps).

%% ------------------------------------------------------------
%% Discovery
%% ------------------------------------------------------------

discover(Identifier) when is_atom(Identifier) ->
    discover(binary_to_list(provider(Identifier)));
discover(Identifier) ->
    Req = case yadis:retrieve(Identifier) of
              {none, NormalizedId, Body} ->
                  html_discovery(NormalizedId, Body);
              #openid_xrds{}=XRDS ->
                  extract_authreq(XRDS);
              {error, _Error} ->
                  %?DBG({error, Error}),
                  none
          end,

    case Req of
        #openid_authreq{} ->
            set_identity_params(Req);
        _ ->
            Req
    end.


extract_authreq(XRDS) ->
    case authreq_by_opid(XRDS) of
        none ->
            authreq_by_claimed_id(XRDS);
        Req ->
            Req
    end.

authreq_by_opid(XRDS) ->
    authreq_by_opid(XRDS, ["http://specs.openid.net/auth/2.0/server",
                           "http://openid.net/server/1.1",
                           "http://openid.net/server/1.0"]).

authreq_by_opid(_, []) -> none;
authreq_by_opid(XRDS, [Type|Rest]) ->
    case find_service(XRDS#openid_xrds.services, Type) of
        none -> authreq_by_opid(XRDS, Rest);
        Service -> build_authReq(XRDS, Service, {2,0})
    end.


find_service([], _) ->
    none;
find_service([#openid_xrdservice{uris=[]}|Rest], Type) ->
    find_service(Rest, Type);
find_service([#openid_xrdservice{types=Types}=Service|Rest], Type) ->
    case lists:any(fun(X) -> X =:= Type end, Types) of
        true -> Service;
        false -> find_service(Rest, Type)
    end.


authreq_by_claimed_id(XRDS) ->
    authreq_by_claimed_id(XRDS,
                          [{"http://specs.openid.net/auth/2.0/signon", {2,0}},
                           {"http://openid.net/signon/1.1", {1,1}},
                           {"http://openid.net/signon/1.0", {1,0}}]).

authreq_by_claimed_id(_, []) ->
    none;
authreq_by_claimed_id(XRDS, [{Type,Version}|Rest]) ->
    case find_service(XRDS#openid_xrds.services, Type) of
        none -> authreq_by_claimed_id(XRDS, Rest);
        Service -> build_authReq(XRDS, Service, Version)
    end.


build_authReq(XRDS, Service, Version) ->
    #openid_authreq{opURLs=Service#openid_xrdservice.uris,
                    version=Version,
                    claimedID=XRDS#openid_xrds.claimedID,
                    localID=Service#openid_xrdservice.localID}.


html_discovery(Id, Body) ->
    html_discovery(Id, Body, [{"openid2.provider", "openid2.local_id", {2,0}},
                              {"openid.server", "openid.delegate", {1,1}}]).

html_discovery(_Id, _, []) ->
    none;
html_discovery(Id, Body, [{ProviderRel, LocalIDRel, Version}|Rest]) ->
    case openid_utils:get_tags(Body, "link", "rel", ProviderRel) of
        [Tag|_] ->
            case ?GVD("href", Tag, none) of
                none -> html_discovery(Body, Rest);
                URL ->
                    LocalID = html_local_id(Body, LocalIDRel),
                    #openid_authreq{opURLs=[URL], version=Version,
                                    localID=LocalID, claimedID=Id}
            end;
        _ -> html_discovery(Id, Body, Rest)
    end.

html_local_id(Body, RelName) ->
    case openid_utils:get_tags(Body, "link", "rel", RelName) of
        [Tag|_] -> ?GVD("href", Tag, none);
        _ -> none
    end.


set_identity_params(AuthReq) ->
    {Claimed, Local} = get_identity_params(AuthReq#openid_authreq.claimedID,
                                           AuthReq#openid_authreq.localID),
    AuthReq#openid_authreq{claimedID=Claimed, localID=Local}.

get_identity_params(none, _) ->
    {"http://specs.openid.net/auth/2.0/identifier_select",
     "http://specs.openid.net/auth/2.0/identifier_select"};
get_identity_params(ClaimedID, none) ->
    {ClaimedID, ClaimedID};
get_identity_params(ClaimedID, LocalID) ->
    {ClaimedID, LocalID}.

%% ------------------------------------------------------------
%% Association
%% ------------------------------------------------------------

% Defaults from spec
-define(P, 1500073708273015748628013388693328252000303842391466352869527958572384115195772928792417592549921617769856041063651334172856114323013748155551037713908795501949688353681514443698908035718685336822727455568028009921661496375944512427).
-define(G, 2).

-define(CONTENT_TYPE, "application/x-www-form-urlencoded; charset=UTF-8").

assoc_handle(#openid_assoc{handle=Handle}) ->
    iolist_to_binary(Handle).

associate(#openid_authreq{opURLs=[OpURL | _]}) ->
    associate(OpURL);
associate(OpURL) ->
    MP = crypto:mpint(?P),
    MG = crypto:mpint(?G),

    {Public, Private} = crypto:dh_generate_key([MP,MG]),

    Params = [{"openid.ns", "http://specs.openid.net/auth/2.0"},
              {"openid.mode", "associate"},
              {"openid.assoc_type", "HMAC-SHA1"},
              {"openid.session_type", "DH-SHA1"},
              {"openid.dh_modulus", base64:encode(roll(MP))},
              {"openid.dh_gen", base64:encode(roll(MG))},
              {"openid.dh_consumer_public", base64:encode(roll(Public))}],

    ReqBody = openid_pm:url_encode(Params),

    {ok, 200, _Headers, Body} = openid_http:post(OpURL, ?CONTENT_TYPE,
                                                 ReqBody),

    Response = openid_pm:kvf_decode(Body),

    Handle = ?GV("assoc_handle", Response),
    ExpiresIn = list_to_integer(?GV("expires_in", Response)),

    ServPublic = unroll(base64:decode(?GV("dh_server_public", Response))),

    %?DBG({serv_pub, ServPublic}),

    EncMAC = base64:decode(?GV("enc_mac_key", Response)),

    ZZ = btwoc(crypto:dh_compute_key(ServPublic, Private, [MP,MG])),

    %?DBG({zz, ZZ}),

    MAC = crypto:exor(crypto:sha(ZZ), EncMAC),

    #openid_assoc{opURL=OpURL,
                  handle=Handle,
                  created=now(),
                  expiresIn=ExpiresIn,
                  servPublic=ServPublic,
                  mac=MAC}.


roll(<<_Size:32, Bin/binary>>) ->
    btwoc(Bin).

%% big endian two's complement
btwoc(<<1:1, _/binary>>=Bin) ->
    <<0, Bin/binary>>;
btwoc(Bin) ->
    Bin.


unroll(Bin) ->
    <<(byte_size(Bin)):32, Bin/binary>>.


%% ------------------------------------------------------------
%% Authentication
%% ------------------------------------------------------------

authentication_url(AuthReq, ReturnTo, Realm, Assoc) ->
    authentication_url(AuthReq, ReturnTo, Realm, Assoc, []).

authentication_url(#openid_authreq{claimedID=ClaimedID,
                                   localID=LocalID},
                   ReturnTo,
                   Realm,
                   #openid_assoc{handle=Handle, opURL=URL},
                   ExtraProps) ->
    Extra = lists:map(fun openid_norm/1, ExtraProps),
    IDBits = case ClaimedID of
                 none ->
                     Extra;
                 _ ->
                     [{"openid.claimed_id", ClaimedID},
                      {"openid.identity", LocalID} | Extra]
             end,
    iolist_to_binary(
      add_qs(
        URL,
        openid_pm:uri_encode(
          [{"openid.ns", "http://specs.openid.net/auth/2.0"},
           {"openid.mode", "checkid_setup"},
           {"openid.assoc_handle", Handle},
           {"openid.return_to", ReturnTo},
           {"openid.realm", Realm} | IDBits]))).

openid_norm({K, V}) when is_binary(K) andalso is_binary(V) ->
    openid_norm({binary_to_list(K), binary_to_list(V)});
openid_norm({K, V}) ->
    {"openid." ++ K, V}.

ax(Attributes) ->
    %% Order shouldn't matter but might as well present the results
    %% in the same order as the input.
    {Fields, Required, IfAvailable} = lists:foldr(fun ax_field/2,
                                                  {[], [], []},
                                                  Attributes),
    lists:append(
      [[{<<"ns.ax">>, ns(ax)},
        {<<"ax.mode">>, <<"fetch_request">>}],
       field_list(<<"ax.required">>, Required),
       field_list(<<"ax.if_available">>, IfAvailable),
       Fields]).

%% https://developers.google.com/accounts/docs/OpenID#Parameters
ns(ax) ->
    <<"http://openid.net/srv/ax/1.0">>;
ns(pape) ->
    <<"http://specs.openid.net/extensions/pape/1.0">>.

provider(google) ->
    <<"https://www.google.com/accounts/o8/id">>.

ax_schema(country) ->
    <<"http://axschema.org/contact/country/home">>;
ax_schema(email) ->
    <<"http://axschema.org/contact/email">>;
ax_schema(firstname) ->
    <<"http://axschema.org/namePerson/first">>;
ax_schema(language) ->
    <<"http://axschema.org/pref/language">>;
ax_schema(lastname) ->
    <<"http://axschema.org/namePerson/last">>.

ax_output(Name, Output) ->
    [{<<"ax.type.", (atom_to_binary(Name, utf8))/binary>>, ax_schema(Name)}
     | Output].

ax_field({Name, required}, {Output, Required, IfAvailable}) ->
    {ax_output(Name, Output), [Name | Required], IfAvailable};
ax_field({Name, if_available}, {Output, Required, IfAvailable}) ->
    {ax_output(Name, Output), Required, [Name | IfAvailable]};
ax_field(Name, {Output, Required, IfAvailable}) when is_atom(Name) ->
    {ax_output(Name, Output), [Name | Required], IfAvailable}.

field_list(Name, [First | Rest]) ->
    [{Name,
      iolist_to_binary([atom_to_binary(First, utf8)
                        | [[$,, atom_to_binary(Elem, utf8)]
                           || Elem <- Rest]])}];
field_list(_Name, []) ->
    [].

add_qs(Rest="?" ++ _, QueryString) ->
    [Rest, [$& | QueryString]];
add_qs([C | Rest], QueryString) ->
    [C | add_qs(Rest, QueryString)];
add_qs([], QueryString) ->
    [$? | QueryString].

%% ------------------------------------------------------------
%% Verification
%% ------------------------------------------------------------

verify(RawReturnTo, #openid_assoc{handle=Handle, mac=MAC}, RawFields) ->
    %% TODO: verify that the claimed_id is what we want
    try verify_norm(normalize_url(RawReturnTo),
                    {iolist_to_binary(Handle), MAC},
                    normalize_fields(RawFields))
    catch throw:Err ->
            Err
    end.

normalize_url(URL) when is_list(URL) ->
    list_to_binary(URL);
normalize_url(URL) ->
    URL.

normalize_fields([]) ->
    [];
normalize_fields([{K, V} | Rest]) when is_list(K) andalso is_list(V) ->
    normalize_fields([{list_to_binary(K), list_to_binary(V)} | Rest]);
normalize_fields([{<<"openid.", K/binary>>, V} | Rest]) when is_binary(V) ->
    [{K, V} | normalize_fields(Rest)];
normalize_fields([_KV | Rest]) ->
    normalize_fields(Rest).

split_comma(B) ->
    binary:split(B, <<",">>, [global]).

verify_norm(ReturnTo, {Handle, MAC}, Fields) ->
    expect_field(<<"return_to">>, ReturnTo, Fields),
    expect_field(<<"assoc_handle">>, Handle, Fields),
    Signed = split_comma(get_field(<<"signed">>, Fields)),
    Sig = get_field(<<"sig">>, Fields),
    eq("sig",
       sign(MAC, Signed, Fields),
       try base64:decode(Sig)
       catch error:_ ->
               {invalid_base64, Sig}
       end),
    eq("missing signature for required fields",
       [],
       [<<"assoc_handle">>, <<"claimed_id">>,
        <<"response_nonce">>, <<"return_to">>] -- Signed),
    Fields.

verify_ax(Attributes, Fields) ->
    {_Out, Required, IfAvailable} = lists:foldr(fun ax_field/2,
                                                {[], [], []},
                                                Attributes),
    {NSName=(<<"ns.", NS/binary>>), _} = lists:keyfind(ns(ax), 2, Fields),
    Prefix = <<NS/binary, ".">>,
    PLen = byte_size(Prefix),
    Signed = split_comma(get_field(<<"signed">>, Fields)),
    %% Verify that all AX fields are signed
    eq("missing signature for ax",
       [],
       [NSName |
        [K || {K=(<<P:PLen/binary, _/binary>>), _V} <- Fields,
              P =:= Prefix]] -- Signed),
    AXFields = [{K, V} || {<<P:PLen/binary, K/binary>>, V} <- Fields,
                          P =:= Prefix],
    expect_field(<<"mode">>, <<"fetch_response">>, AXFields),
    lists:append(
      [fetch_ax(Required, AXFields, true),
       fetch_ax(IfAvailable, AXFields, false)]).

fetch_ax([Name | Rest], AXFields, Required) ->
    NameB = atom_to_binary(Name, utf8),
    case lists:keyfind(<<"value.", NameB/binary>>, 1, AXFields) of
        {_, Value} ->
            %% Ensure that the schema is what we asked for
            expect_field(<<"type.", NameB/binary>>,
                         ax_schema(Name),
                         AXFields),
            [{Name, Value} | fetch_ax(Rest, AXFields, Required)];
        false when Required =:= false ->
            fetch_ax(Rest, AXFields, Required);
        false ->
            throw({error, {missing_ax_value, Name}})
    end;
fetch_ax([], _AXFields, _Required) ->
    [].

sign(MAC, Signed, Fields) ->
    crypto:sha_mac(
      MAC,
      [[K, $:, get_field(K, Fields), $\n]
       || K <- Signed]).

get_field(K, Fields) ->
    case lists:keyfind(K, 1, Fields) of
        {_, V} ->
            V;
        false ->
            throw({error, {missing_field, K}})
    end.

expect_field(K, Expect, Fields) ->
    eq(K, Expect, get_field(K, Fields)).

eq(_K, Expect, Value) when Value =:= Expect ->
    Value;
eq(K, Expect, Value) ->
    throw({error, {badmatch,
                   [{field, K},
                    {expect, Expect},
                    {value, Value}]}}).
