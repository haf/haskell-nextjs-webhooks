{-# LANGUAGE DeriveGeneric #-}
module Main where

import Lib
import System.Envy
import GHC.Generics
import qualified Data.ByteString.UTF8 as BSU

data AppConfig = AppConfig {
        adminKey :: String -- "ADMIN_KEY"
    } deriving (Generic, Show)

-- All fields will be converted to uppercase
getConfig :: IO (Either String AppConfig)
getConfig =
    let reader = gFromEnvCustom defOption (Just (AppConfig "admin_EF5AD17A-281C-4708-A004-394E1A5FECBA"))
    in runEnv reader

main :: IO ()
main = do
    config <- getConfig
    case config of
        Left err ->
            putStrLn err
        Right c -> do
            putStrLn ("Using admin key: " ++ adminKey c)
            example (BSU.fromString $ adminKey c)
