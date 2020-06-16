{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE OverloadedStrings #-}

module Lib
    ( example
    ) where

import Crypto.Hash (hash)
import Crypto.Hash.Algorithms (MD5, SHA256)
import Crypto.Hash.IO (HashAlgorithm)
import Crypto.MAC.HMAC (HMAC (hmacGetDigest), hmac)
import Data.List (sort, uncons)
import Data.ByteString (ByteString)

import Control.Monad.IO.Class
import Data.Aeson as E
import Network.HTTP.Req as Req

import qualified Crypto.MAC.HMAC as HM
import qualified Data.ByteArray as BA
import qualified Data.ByteString.Base16 as Hex
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as Lazy
import qualified Data.ByteString.UTF8 as BSU
import qualified Network.HTTP.Types as Y
import qualified Network.HTTP.Client as L

hmacSHA256 :: ByteString -- ^ Secret key to use
           -> ByteString -- ^ Message to MAC
           -> ByteString -- ^ Hashed message
hmacSHA256 sk msg =
    let digest = hmacGetDigest (HM.hmac sk msg :: HMAC SHA256)
    in let bs = BA.convert digest
    in Hex.encode bs

normalise :: ByteString -> ByteString -> ByteString -> ByteString
normalise url method body =
    BS.intercalate "\n" [
        method
    ,   url
    ,   body
    ]

instance Show POST where
    show v = "POST"

example :: ByteString -> IO ()
example adminKey = runReq defaultHttpConfig $ do
    let actionName = "hello"
    let url = "http://localhost:3000/api/hello"
    let method = POST
    let payload = E.object [ "message" .= ("Hello!" :: String) ]
    let message = let m = B.pack (show method)
                  in normalise url m (Lazy.toStrict $ E.encode payload)

    let actionKey = hmacSHA256 adminKey actionName
    let messageSignature = hmacSHA256 actionKey message

    liftIO $ do
        putStrLn ""
        putStrLn "Normalised message:"
        putStrLn "---"
        B.putStrLn message
        putStrLn "---"
        putStrLn ""
        putStrLn "Using shared action key: "
        B.putStrLn actionKey
        putStrLn "As bytes: "
        B.putStrLn (Hex.encode actionKey)
        putStrLn ""

    let options = port 3000 <> header "hmac" messageSignature
    r <- req method (http "localhost" /: "api" /: "hello") (ReqBodyJson payload) jsonResponse options

    liftIO $ print (responseBody r :: Value)