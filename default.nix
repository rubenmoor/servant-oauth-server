{ mkDerivation, aeson, base, bytestring, Cabal, http-api-data
, http-client, http-types, jose, lens, mtl, reflex-dom-core
, servant, servant-reflex, servant-server, stdenv, text, time
, unordered-containers, wai
}:
mkDerivation {
  pname = "servant-oauth-server";
  version = "0.1.0.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base bytestring Cabal http-api-data http-client http-types
    jose lens mtl reflex-dom-core servant servant-reflex servant-server
    text time unordered-containers wai
  ];
  homepage = "https://github.com/george-steel/servant-oauth-server#readme";
  description = "OAuth2 bearer token auth and token endpoint for Servant";
  license = stdenv.lib.licenses.bsd3;
}
