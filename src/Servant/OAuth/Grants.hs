{-# LANGUAGE FlexibleContexts, FlexibleInstances, MultiParamTypeClasses, ScopedTypeVariables, GeneralizedNewtypeDeriving, GADTs, TypeFamilies, TypeApplications, DataKinds, OverloadedStrings, ExtendedDefaultRules, OverloadedLists, LambdaCase #-}

{-|
Module: Servant.OAuth.Grants
Description: OAuth2 grant and response types
Copyright: © 2018-2019 Satsuma labs, 2019 George Steel

This module data types and serialization instances for OAuth token requests and responses.
The serialization instances require/emit the correct @grant_type@ parameter and marsers may be combined using '(<|>)' for sum types.
(@sumEncoding = UntaggedValue@ may also be uused if using Aeson TH or Generic instances).

-}




module Servant.OAuth.Grants where


import Data.Text (Text, unpack, pack)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.HashMap.Strict as H
import Control.Arrow
import Control.Applicative
import Control.Monad.Except (throwError)
--import Control.Lens
import Data.Proxy
import Web.HttpApiData
import Web.FormUrlEncoded
import Data.Aeson
import Data.Maybe
import Data.Time
import GHC.TypeLits
import Data.Aeson.Types (typeMismatch, prependFailure)

default(Text)

-- | Created a 'Form' with a single parameter. Combine results using the 'Monoid' instance to create more complex 'Form's.
param :: (ToHttpApiData a) => Text -> a -> Form
param k x = Form (H.singleton k [toQueryParam x])

-- | Encode a 'Form' to a URL query string including the initial question mark.
qstring :: Form -> B.ByteString
qstring f = BL.toStrict $ "?" <> urlEncodeForm f


-- * Tokens

-- | Reperesents a compact-encoded JWT access tokens token in requests and responses. Header encoding includes @Bearer@ prefix.
newtype CompactJWT = CompactJWT Text deriving (Eq, Show, FromJSON, ToJSON)
instance (FromHttpApiData CompactJWT) where
    parseQueryParam = Right . CompactJWT
    parseHeader h = (pack . show +++ CompactJWT) . T.decodeUtf8' . fromMaybe h $ B.stripPrefix "Bearer " h
instance (ToHttpApiData CompactJWT) where
    toQueryParam (CompactJWT t) = t
    toHeader (CompactJWT t) = "Bearer " <> T.encodeUtf8 t

-- | Type for opaque access tokens. Header encoding includes @Bearer@ prefix.
newtype OpaqueToken = OpaqueToken Text deriving (Eq, Ord, Show, FromJSON, ToJSON)
instance (FromHttpApiData OpaqueToken) where
    parseQueryParam = Right . OpaqueToken
    parseHeader h = (pack . show +++ OpaqueToken) . T.decodeUtf8' . fromMaybe h $ B.stripPrefix "Bearer " h
instance (ToHttpApiData OpaqueToken) where
    toQueryParam (OpaqueToken t) = t
    toHeader (OpaqueToken t) = "Bearer " <> T.encodeUtf8 t

-- | Type for refresh tokens. These are always opaque and not used in Authorization headers.
newtype RefreshToken = RefreshToken Text
    deriving (Ord, Eq, Read, Show, ToHttpApiData, FromHttpApiData, ToJSON, FromJSON)


-- | Successful response type for OAuth token endpoints
data OAuthTokenSuccess = OAuthTokenSuccess {
    oauth_access_token :: CompactJWT,
    oauth_expires_in :: NominalDiffTime,
    oauth_refresh_token :: Maybe RefreshToken}
    deriving (Eq, Show)

instance ToJSON OAuthTokenSuccess where
    toJSON (OAuthTokenSuccess tok expt mrtok) = Object $
        "access_token" .= tok <> "expires_in" .= expt <> maybe mempty ("refresh_token" .=) mrtok

instance FromJSON OAuthTokenSuccess where
    parseJSON = withObject "OAuthTokenSuccess" $ \o -> OAuthTokenSuccess
        <$> o .: "access_token"
        <*> o .: "expires_in"
        <*> o .:? "refresh_token"

-- * Errors

-- | OAuth error codes.
data OAuthErrorCode =
    InvalidGrantRequest
    | InvalidClient
    | InvalidGrant
    | InvalidScope
    | UnauthorizedClient
    | UnsupportedGrantType
    | InvalidTarget
    | TemporarilyUnavailable
    deriving (Eq, Read, Show)

-- | Failure response for OAuth token endpoints. Serialize this as the body of an error response.
data OAuthFailure = OAuthFailure {
    oauth_error :: OAuthErrorCode,
    oauth_error_description :: Maybe Text,
    oauth_error_uri :: Maybe Text}
    deriving (Eq, Read, Show)

instance ToJSON OAuthErrorCode where
    toJSON InvalidGrantRequest = "invalid_request"
    toJSON InvalidClient = "invalid_client"
    toJSON InvalidGrant = "invalid_grant"
    toJSON InvalidScope = "invalid_scope"
    toJSON UnauthorizedClient = "unauthorized_client"
    toJSON UnsupportedGrantType = "unsupported_grant_type"
    toJSON InvalidTarget = "invalid_target"
    toJSON TemporarilyUnavailable = "temporarily_unavailable"

instance FromJSON OAuthErrorCode where
  parseJSON = \case
    "invalid_request"         -> pure InvalidGrantRequest
    "invalid_client"          -> pure InvalidClient
    "invalid_grant"           -> pure InvalidGrant
    "invalid_scope"           -> pure InvalidScope
    "unauthorized_client"     -> pure UnauthorizedClient
    "unsupported_grant_type"  -> pure UnsupportedGrantType
    "invalid_target"          -> pure InvalidTarget
    "temporarily_unavailable" -> pure TemporarilyUnavailable
    invalid ->
      prependFailure "parsing message failed, " (typeMismatch "String" invalid)

instance ToJSON OAuthFailure where
    toJSON (OAuthFailure err mdesc muri) = Object $
         "error" .= err
      <> maybe mempty ("error_description" .=) mdesc
      <> maybe mempty ("error_uri" .=) muri

instance FromJSON OAuthFailure where
  parseJSON (Object v) = OAuthFailure
    <$> v .: "error"
    <*> v .:? "error_description"
    <*> v .:? "error_uri"
  parseJSON invalid =
    prependFailure "parsing message failed, " (typeMismatch "Object" invalid)

-- * Grants

-- | Client identifier for third party clients.
newtype OAuthClientId = OAuthClientId Text
    deriving (Ord, Eq, Read, Show, ToHttpApiData, FromHttpApiData, ToJSON, FromJSON)

-- | Resource owner credentials grant.
data OAuthGrantPassword = OAuthGrantPassword {
    gpw_username :: Text,
    gpw_password :: Text }
    deriving (Eq)

-- | Custom assertion grant parameterized by grant_type (which according to spec should be a URI).
-- Used for federated login with identity providers returning opaque tokens (such as Facebook).
newtype OAuthGrantOpaqueAssertion (grant_type :: Symbol) = OAuthGrantOpaqueAssertion OpaqueToken
    deriving (Eq, Show, FromHttpApiData, ToHttpApiData)

-- | JWT assertion grant. Use this for OpenID Connect @id_token@s.
newtype OAuthGrantJWTAssertion = OAuthGrantJWTAssertion CompactJWT

-- | Refresh token grant
newtype OAuthGrantRefresh = OAuthGrantRefresh RefreshToken

-- | Authorization code grant with PKCE verifier.
data OAuthGrantCodePKCE = OAuthGrantCodePKCE {
    gcp_code :: Text,
    gcp_code_verifier :: Text
}

-- | Adds a scope restriction to a grant.
data WithScope s a = WithScope (Maybe s) a


instance FromJSON OAuthGrantPassword where
    parseJSON = withObject "password" $ \o ->
        o .: "grant_type" >>= \gt ->
            if gt == "password"
            then OAuthGrantPassword <$> o .: "username" <*> o .: "password"
            else fail "wrong grant type"

instance (KnownSymbol gt) => FromJSON (OAuthGrantOpaqueAssertion gt) where
    parseJSON = withObject ("assert_opaque:" <> symbolVal (Proxy @gt)) $ \o ->
        o .: "grant_type" >>= \pgt ->
            if pgt == symbolVal (Proxy @gt)
            then OAuthGrantOpaqueAssertion <$> o .: "assertion"
            else fail "wrong grant type"

instance FromJSON OAuthGrantJWTAssertion where
    parseJSON = withObject "assert_jwt" $ \o ->
        o .: "grant_type" >>= \gt ->
            if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer"
            then OAuthGrantJWTAssertion <$> o .: "assertion"
            else fail "wrong grant type"

instance FromJSON OAuthGrantCodePKCE where
    parseJSON = withObject "code_pkce" $ \o ->
        o .: "grant_type" >>= \gt ->
            if gt == "authorization_code"
            then OAuthGrantCodePKCE <$> o .: "code" <*> o .: "code_verifier"
            else fail "wrong grant type"

instance FromJSON OAuthGrantRefresh where
    parseJSON = withObject "assert_jwt" $ \o ->
        o .: "grant_type" >>= \gt ->
            if gt == "refresh_token"
            then OAuthGrantRefresh <$> o .: "refresh_token"
            else fail "wrong grant type"

instance (FromJSON s, FromJSON a) => FromJSON (WithScope s a) where
    parseJSON v@(Object o) = WithScope <$> o .:? "scope" <*> parseJSON v
    parseJSON v = WithScope Nothing <$> parseJSON v


instance ToJSON OAuthGrantPassword where
    toJSON (OAuthGrantPassword un pw) = object ["grant_type" .= "password", "username" .= un, "password" .= pw]

instance (KnownSymbol gt) => ToJSON (OAuthGrantOpaqueAssertion gt) where
    toJSON (OAuthGrantOpaqueAssertion x) = object ["grant_type" .= symbolVal (Proxy @gt), "assertion" .= x]

instance ToJSON OAuthGrantJWTAssertion where
    toJSON (OAuthGrantJWTAssertion x) = object ["grant_type" .= "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion" .= x]

instance ToJSON OAuthGrantCodePKCE where
    toJSON (OAuthGrantCodePKCE code ver) = object ["grant_type" .= "authorization_code", "code" .= code, "code_verifier" .= ver]

instance ToJSON OAuthGrantRefresh where
    toJSON (OAuthGrantRefresh x) = object ["grant_type" .= "refresh_token", "refresh_token" .= x]

instance (ToJSON s, ToJSON a) => ToJSON (WithScope s a) where
    toJSON (WithScope Nothing x) = toJSON x
    toJSON (WithScope (Just s) x) = let Object o = toJSON x in Object (H.insert "scope" (toJSON x) o)


instance FromForm OAuthGrantPassword where
    fromForm f = lookupUnique "grant_type" f >>= \gt ->
        if gt == "password"
        then OAuthGrantPassword <$> parseUnique "username" f <*> parseUnique "password" f
        else throwError "wrong grant type"

instance (KnownSymbol gt) => FromForm (OAuthGrantOpaqueAssertion gt) where
    fromForm f = parseUnique "grant_type" f >>= \pgt ->
        if pgt == symbolVal (Proxy @gt)
        then OAuthGrantOpaqueAssertion <$> parseUnique "assertion" f
        else throwError "wrong grant type"

instance FromForm OAuthGrantJWTAssertion where
    fromForm f = lookupUnique "grant_type" f >>= \gt ->
        if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        then OAuthGrantJWTAssertion <$> parseUnique "assertion" f
        else throwError "wrong grant type"

instance FromForm OAuthGrantCodePKCE where
    fromForm f = lookupUnique "grant_type" f >>= \gt ->
        if gt == "authorization_code"
        then OAuthGrantCodePKCE <$> parseUnique "code" f <*> parseUnique "code_verifier" f
        else throwError "wrong grant type"

instance FromForm OAuthGrantRefresh where
    fromForm f = lookupUnique "grant_type" f >>= \gt ->
        if gt == "refresh_token"
        then OAuthGrantRefresh <$> parseUnique "refresh_token" f
        else throwError "wrong grant type"

instance (FromHttpApiData s, FromForm a) => FromForm (WithScope s a) where
    fromForm f = WithScope <$> parseMaybe "scope" f <*> fromForm f


instance ToForm OAuthGrantPassword where
    toForm (OAuthGrantPassword un pw) = param "grant_type" "password" <> param "username" un <> param "password" pw

instance (KnownSymbol gt) => ToForm (OAuthGrantOpaqueAssertion gt) where
    toForm (OAuthGrantOpaqueAssertion x) = param "grant_type" (symbolVal (Proxy @gt)) <> param "assertion" x

instance ToForm OAuthGrantJWTAssertion where
    toForm (OAuthGrantJWTAssertion x) = param "grant_type" "urn:ietf:params:oauth:grant-type:jwt-bearer" <> param "assertion" x

instance ToForm OAuthGrantCodePKCE where
    toForm (OAuthGrantCodePKCE code ver) = param "grant_type" "authorization_code" <> param "code" code <> param "code_verifier" ver

instance ToForm OAuthGrantRefresh where
    toForm (OAuthGrantRefresh x) = param "grant_type" "refresh_token" <> param "refresh_token" x

instance (ToHttpApiData s, ToForm a) => ToForm (WithScope s a) where
    toForm (WithScope s x) = maybe mempty (param "scope") s <> toForm x
