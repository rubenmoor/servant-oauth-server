{-# LANGUAGE FlexibleContexts, FlexibleInstances, MultiParamTypeClasses, ScopedTypeVariables, GeneralizedNewtypeDeriving,
    GADTs, TypeFamilies, TypeApplications, DefaultSignatures, TypeOperators, DataKinds,
    OverloadedStrings, ExtendedDefaultRules, LambdaCase, TemplateHaskell #-}

{-|
Module: Servant.OAuth.Server.Facebook
Description: Facebook access token verification
Copyright: © 2018-2019 Satsuma labs, 2019 George Steel

Defines 'checkFacebookAssertion' and sup[porting types which allow facebook access tokens to be verified as assertions for federated login.
Uses [verification procedure](https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow/) defined in the facebook login docs.
-}

module Servant.OAuth.Server.Facebook (
    OAuthGrantFacebookAssertion, FacebookUserId(..), FacebookSettings(..),
    checkFacebookAssertion, getFacebookUserInfo,
    FacebookUserInfo(..), FacebookTokenCheck(..), FacebookError(..)
) where

import Data.Text (Text)
import qualified Data.ByteString.Lazy as BL
import Control.Monad.IO.Class
import Control.Monad.Except
import Control.Exception
import Web.HttpApiData
import Data.Aeson
import Data.Aeson.TH
import Data.Time
import Data.Time.Clock.POSIX

import Network.HTTP.Client
import Servant.Server (ServerError, err502, err401)

import Servant.OAuth.Server
import Servant.OAuth.Server.TokenEndpoint
import Servant.OAuth.Grants

-- | Specialization of opaque grant assertion for facebook access tokens.
type OAuthGrantFacebookAssertion = OAuthGrantOpaqueAssertion "https://graph.facebook.com/oauth/access_token"

-- | Type for facebook user IDs
newtype FacebookUserId = FacebookUserId Text deriving (Eq, Ord, Read, Show, ToJSON, FromJSON, ToHttpApiData, FromHttpApiData)

-- | @data:@ wrapper for fb response
newtype FBData a = FBData {fb_data :: a} deriving (Show)
deriveFromJSON (defaultOptions {fieldLabelModifier = drop 3}) ''FBData

-- | Facebook error message format
data FacebookError = FacebookError {
    fberr_code :: Int,
    fberr_message :: Text
} deriving (Show)
deriveFromJSON (defaultOptions {fieldLabelModifier = drop 6}) ''FacebookError

-- | Facebook @/degug_token@ response
data FacebookTokenCheck = RecognisedToken {
    ftc_is_valid :: Bool,
    ftc_app_id :: OAuthClientId,
    ftc_user_id :: FacebookUserId,
    ftc_type :: Text,
    ftc_application :: Text,
    ftc_expires_at :: POSIXTime,
    ftc_scopes :: [Text],
    ftc_error :: Maybe FacebookError
} | BogusToken {
    ftc_is_valid :: Bool,
    ftc_error :: Maybe FacebookError
} deriving (Show)
deriveFromJSON (defaultOptions {fieldLabelModifier = drop 4, sumEncoding = UntaggedValue}) ''FacebookTokenCheck

-- | Facebook user info from @/me@ endpoint
data FacebookUserInfo = FacebookUserInfo {
    fb_id :: FacebookUserId,
    fb_name :: Text,
    fb_short_name :: Text,
    fb_email :: Maybe Text
} deriving (Show)
deriveJSON (defaultOptions {fieldLabelModifier = drop 3, sumEncoding = UntaggedValue}) ''FacebookUserInfo

-- | Facebook API settings. Includes HTTPS connection manager, app id, and app token provider
data FacebookSettings = FacebookSettings {
    fbHttp :: Manager,
    fbAppId :: OAuthClientId,
    fbTokenProvider :: IO OpaqueToken
}

-- | Checks a facebook access token and return its user ID as well as the raw response (which includes user info).
-- Throws invalid grant if token is invalid, expired, ro for the wrong app id.
checkFacebookAssertion :: (MonadIO m, MonadError ServerError m) => FacebookSettings -> OAuthGrantFacebookAssertion -> m (FacebookUserId, FacebookTokenCheck)
checkFacebookAssertion settings (OAuthGrantOpaqueAssertion tok) = do
    atok <- liftIO $ fbTokenProvider settings
    let req = (parseRequest_ "https://graph.facebook.com/debug_token") {
            queryString = qstring $ param "input_token" tok,
            requestHeaders = [("Authorization", toHeader atok),
                              ("Accept", "application/json")],
            checkResponse = throwErrorStatusCodes}
    mresp :: Either HttpException (Response BL.ByteString) <- liftIO . try $ httpLbs req (fbHttp settings)
    result <- case mresp of
        Left e -> do
            liftIO . putStrLn $ "Error checking facebook token: " ++ show e
            throwServantErrJSON err502 $ OAuthFailure TemporarilyUnavailable (Just "Error contacting Facebook") Nothing
        Right resp -> case decode' (responseBody resp) of
            Nothing -> do
                liftIO . putStrLn $ "Error decoding facebook token check"
                throwServantErrJSON err502 $ OAuthFailure TemporarilyUnavailable (Just "Error decoding facebook token check") Nothing
            Just (FBData x) -> return x
    uid <- case result of
        BogusToken {} -> throwServantErrJSON err401 $ OAuthFailure InvalidGrant (Just "Unrecognised Facebook token") Nothing
        RecognisedToken {ftc_is_valid = valid}
            | valid -> return (ftc_user_id result)
            | otherwise -> throwServantErrJSON err401 $ OAuthFailure InvalidGrant (Just "Invalid Facebook token") Nothing
    return (uid, result)

-- | Retrieves user info given a valid facebook token. Use this to get infor cor creating a new user entry.
getFacebookUserInfo :: (MonadIO m, MonadError ServerError m) => FacebookSettings -> OAuthGrantFacebookAssertion -> m FacebookUserInfo
getFacebookUserInfo settings (OAuthGrantOpaqueAssertion tok) = do
    let req = (parseRequest_ "https://graph.facebook.com/v3.2/me?fields=id,name,short_name,email") {
            requestHeaders = [("Authorization", toHeader tok), ("Accept", "application/json")]}
    mresp :: Either HttpException (Response BL.ByteString) <- liftIO . try $ httpLbs req (fbHttp settings)
    case mresp of
        Left _ -> throwServantErrJSON err502 $ OAuthFailure TemporarilyUnavailable (Just "Error contacting Facebook") Nothing
        Right resp -> case decode' (responseBody resp) of
            Nothing -> throwServantErrJSON err401 $ OAuthFailure InvalidGrant (Just "Unable to fetch registration info") Nothing
            Just u -> return u
