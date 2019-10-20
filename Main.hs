{-
   Simon Zeng
   contact@simonzeng.com
   
   Parses market UDP quote packets and prints relevant info.
   Optional -r flag re-orders packets based on quote acceptance time.

   Compiles without warnings in GHC 8.6.5 on Arch Linux.
   No external packages used.

   Note: since quote time doesn't have info about date, we normalize
   output so that both pkt-time and accept-time print just times w/o dates

   Licensed under your choice of any BSD or MIT license
-}

module Main where

import Data.Binary.Get
import Data.ByteString (ByteString)
import Data.List
import Data.Ord
import Data.Time.Clock.POSIX 
import Data.Time.Format
import System.Environment
import System.IO
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Char8 as BSC

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- Stateless components
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- Type, Data, formatting, and constant declarations
--------------------------------------------------------------------------------

data AskBid = AskBid {qty :: Double, price :: Double}
instance Show AskBid where show x = show (qty x) ++ "@" ++ show (price x)

type AskBids = [AskBid]

toString :: AskBids -> String
toString = intercalate " " . map show

type Ask  = AskBid
type Bid  = AskBid
type Asks = AskBids
type Bids = AskBids
type ISIN = String

type UnixTimestamp = Integer
type HHMMSSuuTimestamp = String

prettyFormat :: HHMMSSuuTimestamp -> String
prettyFormat = intercalate ":" . chunkBy 2 

data QuoteInfo = QuoteInfo {
    pkt_time    :: HHMMSSuuTimestamp,
    acpt_time   :: HHMMSSuuTimestamp,
    issue_code  :: ISIN,
    sorted_bids :: Bids,
    sorted_asks :: Asks
} 

quote_formatters :: [QuoteInfo -> String]
quote_formatters = [
    prettyFormat . pkt_time,
    prettyFormat . acpt_time,
    issue_code,
    toString . sorted_bids,
    toString . sorted_asks
 ]

instance Show QuoteInfo where show = intercalate " " . sequence quote_formatters
instance Eq QuoteInfo where (==) a b = (acpt_time a) == (acpt_time b) -- needed for ord
instance Ord QuoteInfo where compare = comparing acpt_time


data PcapHeader = PcapHeader {
    header_seconds  :: Seconds,
    header_useconds :: Useconds,
    size            :: Int
 }

type Useconds       = Integer
type Centiseconds   = Integer
type Seconds        = Integer
type TimeoutSeconds = Int
type UnixTimeTuple  = (UnixTimestamp, Useconds)

data SliceType  = Isin | Time | BidSlice | AskSlice 

-- the slicetype field here is entirely decorational
data QuoteSlice = QuoteSlice SliceType (Int, Int)

type SliceExtractor = ByteString -> String

type PacketAction = [QuoteInfo] -> PcapHeader -> ByteString -> IO [QuoteInfo]

quote_magic_string :: ByteString
quote_magic_string = BSC.pack "B6034"

delay_buffer :: Centiseconds
delay_buffer = 300

packet_timeout :: TimeoutSeconds -- for converting to real udp :)
packet_timeout = 5

help_msg :: String
help_msg = "usage: ./parse_quote [-r] <pcap file>"

-- location of values inside a quote body
-- I hope I did my math correctly...
-- Luckily if I didn't, this part of the code is the only part I have to change
quote_slices :: [QuoteSlice]
quote_slices = [
    QuoteSlice Isin (0, 12),
    QuoteSlice Time (201, 208),
    QuoteSlice BidSlice (24, 83),
    QuoteSlice AskSlice (91, 150)
 ]

japan_gmt_offset :: Seconds
japan_gmt_offset = 32400

--------------------------------------------------------------------------------
-- Data manipulation
--------------------------------------------------------------------------------

bs_substr :: Int -> Int -> ByteString -> ByteString
bs_substr a b bs = BS.take (b-a+1) $ BS.drop a bs

chunkBy :: Int -> [a] -> [[a]]
chunkBy _ [] = []
chunkBy n lst = chunk : chunkBy n rest
    where (chunk, rest) = splitAt n lst

toAskBid :: (String, String) -> AskBid
toAskBid (priceStr, quantityStr) = AskBid (read quantityStr) (read priceStr)

process_asks :: String -> AskBids
process_bids :: String -> AskBids
process_asks = (map $ toAskBid . splitAt 5) . chunkBy 12
process_bids = reverse . process_asks

fromUnixTime :: UnixTimeTuple -> HHMMSSuuTimestamp
fromUnixTime (t, u) = formatTime defaultTimeLocale time_format utc_time
    where
        offset_corrected_time = t + japan_gmt_offset
        utc_time              = posixSecondsToUTCTime $ realToFrac offset_corrected_time
        time_format           = "%H%M%S" ++ take 2 (show u)

sufficiently_old :: HHMMSSuuTimestamp -> QuoteInfo -> Bool
sufficiently_old packet_time quote = packet_cseconds - quote_cseconds > delay_buffer
    where
        packet_cseconds = read packet_time
        quote_time      = acpt_time quote
        quote_cseconds  = read quote_time

--------------------------------------------------------------------------------
-- Data extraction
--------------------------------------------------------------------------------

make_slice_extractor :: QuoteSlice -> SliceExtractor
make_slice_extractor (QuoteSlice _ (a, b)) = BSC.unpack . bs_substr a b

extract_isin        :: SliceExtractor
extract_accept_time :: SliceExtractor
extract_raw_bids    :: SliceExtractor
extract_raw_asks    :: SliceExtractor
[extract_isin, extract_accept_time, extract_raw_bids, extract_raw_asks]
  = map make_slice_extractor quote_slices

extract_bids ::  ByteString -> Bids
extract_asks ::  ByteString -> Asks
extract_bids = process_bids . extract_raw_bids
extract_asks = process_asks . extract_raw_asks

extract_info :: UnixTimeTuple -> ByteString -> QuoteInfo
extract_info time_tuple pkt_body = QuoteInfo packet_time accept_time isin_code bids asks
    where
        packet_time              = fromUnixTime time_tuple
        [accept_time, isin_code] = sequence [extract_accept_time, extract_isin] pkt_body
        [bids, asks]             = sequence [extract_bids, extract_asks]        pkt_body

getPcapHeader :: Get PcapHeader
getPcapHeader = do
    seconds     <- getWord32le
    useconds    <- getWord32le
    packet_size <- getWord32le
    return      $  PcapHeader (fromIntegral seconds)
                              (fromIntegral useconds)
                              (fromIntegral packet_size)

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- Stateful components
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

-- pcap file looper
loop_until_eol :: PacketAction -> Handle -> IO ()
loop_until_eol packet_action handle = do
    _ <- BS.hGet handle 24 -- discard global file header
    pcap_loop [] handle
        where
            pcap_loop :: [QuoteInfo] -> Handle -> IO ()
            pcap_loop acc pcap_file = do
                is_eof <- hIsEOF pcap_file
                if is_eof then mapM_ print acc else process_pcap acc pcap_file

            process_pcap :: [QuoteInfo] -> Handle -> IO ()
            process_pcap acc pcap_file = do
                raw_header <- BSL.hGet pcap_file 16 -- pcap packet header is 16 bytes
                let header = runGet getPcapHeader raw_header
                bytes      <- BS.hGet pcap_file (size header)
                new_acc    <- packet_action acc header bytes
                pcap_loop new_acc pcap_file

process_packet :: PacketAction
process_packet _ header data_bytes
  | is_quote_packet = print quote_info >> return [] -- we return [] instead of () to maintain same type interface as the reorder version
  | otherwise       = return []                     -- so that we can reuse loop_until_eol for both
    where
        packet_time                = toInteger $ header_seconds header
        packet_useconds            = toInteger $ header_useconds header
        packet_body                = BS.drop 42 data_bytes -- packet_header includes ethernet, ip, and udp headers
        (quote_header, quote_body) = BS.splitAt 5 packet_body -- extract magic string
        is_quote_packet            = quote_header == quote_magic_string
        quote_info                 = extract_info (packet_time, packet_useconds) quote_body

-- Strategy: maintain accumulator with the invariant that it is always a sorted list of QuoteInfos
-- In particular, the accumulator is a sorted list of every quote we've seen in the past (delay_buffer) seconds.

-- On every new quote, we insert it into the accumulator, then pop&print the prefix of the accumulator
-- that is older than our acceptable delay time.

-- Each print&pop step tends to O(n), and each insertion tends to O(n^2)
-- But since the accumulator only represents the amount of quotes in a fixed time span, then in reality,
-- insertion is O(d^2)=O(1) and print&pop is O(d)=O(1), since d is a constant.
-- (assuming that average quotes/time interval doesn't fluctuate too wildly)

-- There are of course better ways to do this. But this implemetation can run at the same performance
-- indefinitely for pcap dumps of arbitrarily long time intervals.
process_packet_reorder :: PacketAction
process_packet_reorder accumulator header data_bytes 
  | is_quote_packet = mapM_ print safe_packets >> return (insert quote_info fresh_packets) 
  | otherwise       = return accumulator
    where
        packet_time                   = toInteger $ header_seconds header
        packet_useconds               = toInteger $ header_useconds header
        packet_body                   = BS.drop 42 data_bytes -- drops ethernet, ip, and udp headers
        (quote_header, quote_body)    = BS.splitAt 5 packet_body -- extract magic string
        is_quote_packet               = quote_header == quote_magic_string
        quote_info                    = extract_info (packet_time, packet_useconds) quote_body
        (safe_packets, fresh_packets) = span (sufficiently_old $ pkt_time quote_info) accumulator

----------------------------------------------------------------------------------
---- Runtime/Main functions
----------------------------------------------------------------------------------

decide_action :: [String] -> IO ()
decide_action [pcap_file, "-r"] = decide_action ["-r", pcap_file]
decide_action ["-r", pcap_file] = (openFile pcap_file ReadMode) >>= loop_until_eol process_packet_reorder
decide_action [pcap_file]       = (openFile pcap_file ReadMode) >>= loop_until_eol process_packet
decide_action _                 = print help_msg

main :: IO ()
main = getArgs >>= decide_action >> return ()
