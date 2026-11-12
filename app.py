import os
import time
import secrets
import re
import hmac
import hashlib
from urllib.parse import quote
import logging
from typing import Optional, Dict, Any
from urllib.parse import urlparse
import base64

import httpx
from fastapi import FastAPI, Request, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from ytmusicapi import YTMusic
import yt_dlp
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("alexa-ytm")

# Environment variables with smart auto-detection
DOMAIN = os.getenv("DOMAIN", "").strip()
STREAM_SECRET = os.getenv("STREAM_SECRET", "").strip()
if not STREAM_SECRET:
    STREAM_SECRET = secrets.token_hex(16)
    logger.info("STREAM_SECRET was empty: automatically generated a secure random 32-char secret.")

# Default to the user's Skill ID; strictly reject all other callers
ALEXA_SKILL_ID = os.getenv("ALEXA_SKILL_ID", "amzn1.ask.skill.7848da1c-e2dc-4113-889d-01eb5cb61b51").strip()
# Behind Cloudflare Tunnel, Skill ID authorization is standard and prevents signature breakage
VERIFY_ALEXA_SIGNATURE = os.getenv("VERIFY_ALEXA_SIGNATURE", "false").lower() == "true"
COOKIE_FILE = os.getenv("COOKIE_FILE", "/tmp/cookies.txt")
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY", "").strip()
YOUTUBE_COOKIES = os.getenv("YOUTUBE_COOKIES", "").strip()

def format_netscape_cookies(raw_cookies: str) -> str:
    """Ensures flattened/single-line environment variable cookies are properly formatted for Netscape format."""
    content = raw_cookies.replace("\\n", "\n").replace("\\t", "\t")
    if (content.startswith('"') and content.endswith('"')) or (content.startswith("'") and content.endswith("'")):
        content = content[1:-1]
    # Insert newlines before each cookie domain if flattened into a single line
    content = re.sub(r'([^\n])\s+(\.?youtube\.com|\.?google\.com|#HttpOnly_)', r'\1\n\2', content)
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    header = "# Netscape HTTP Cookie File"
    if not lines or header not in lines[0]:
        lines.insert(0, header)
    return "\n".join(lines) + "\n"

if YOUTUBE_COOKIES:
    try:
        clean_cookies = format_netscape_cookies(YOUTUBE_COOKIES.strip())
        with open(COOKIE_FILE, "w", encoding="utf-8") as f:
            f.write(clean_cookies)
        cookie_count = len([l for l in clean_cookies.splitlines() if not l.startswith("#") and l.strip()])
        logger.info(f"Loaded {cookie_count} YouTube authentication cookies into {COOKIE_FILE}")
    except Exception as e:
        logger.error(f"Failed to write YOUTUBE_COOKIES to {COOKIE_FILE}: {e}")

def resolve_domain(request: Request) -> str:
    """Uses configured DOMAIN or auto-detects from request headers."""
    if DOMAIN:
        return DOMAIN
    forwarded = request.headers.get("x-forwarded-host")
    if forwarded:
        return forwarded.split(",")[0].strip()
    host = request.headers.get("host")
    if host:
        return host.strip()
    return "localhost"

# Initialize YTMusic
yt = None
if os.path.exists(COOKIE_FILE) and COOKIE_FILE.endswith(".json"):
    try:
        logger.info(f"Loading authenticated YouTube Music session from {COOKIE_FILE}")
        yt = YTMusic(COOKIE_FILE)
    except Exception as e:
        logger.warning(f"Could not load {COOKIE_FILE} into YTMusic: {e}")

if yt is None:
    logger.info("Initializing public/unauthenticated YouTube Music client")
    yt = YTMusic()

app = FastAPI(title="Alexa YouTube Music Bridge", docs_url=None, redoc_url=None)

# Cache for Amazon certs
CERT_CACHE: Dict[str, x509.Certificate] = {}


def generate_stream_token(video_id: str, duration_sec: int = 14400) -> Dict[str, str]:
    """Generates an HMAC token valid for 4 hours."""
    exp = str(int(time.time()) + duration_sec)
    signature = hmac.new(
        STREAM_SECRET.encode("utf-8"),
        f"{video_id}:{exp}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return {"token": signature, "exp": exp}


def verify_stream_token(video_id: str, token: str, exp: str) -> bool:
    """Verifies HMAC signature and expiration."""
    try:
        if int(exp) < time.time():
            return False
        expected = hmac.new(
            STREAM_SECRET.encode("utf-8"),
            f"{video_id}:{exp}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, token)
    except Exception:
        return False


async def verify_alexa_request(request: Request, raw_body: bytes) -> bool:
    """Verifies Alexa signature according to Amazon specifications."""
    if not VERIFY_ALEXA_SIGNATURE:
        return True

    cert_url = request.headers.get("SignatureCertChainUrl") or request.headers.get("signaturecertchainurl", "")
    signature = request.headers.get("Signature") or request.headers.get("signature", "")

    if not cert_url or not signature:
        logger.warning("Missing Alexa signature headers (SignatureCertChainUrl or Signature)")
        return False

    # Validate cert URL
    parsed_url = urlparse(cert_url)
    if parsed_url.scheme.lower() != "https":
        logger.warning(f"Invalid cert URL scheme: {parsed_url.scheme}")
        return False
    if parsed_url.hostname.lower() != "s3.amazonaws.com":
        logger.warning(f"Invalid cert hostname: {parsed_url.hostname}")
        return False
    if not parsed_url.path.startswith("/echo.api/"):
        logger.warning(f"Invalid cert path: {parsed_url.path}")
        return False
    if parsed_url.port and parsed_url.port != 443:
        logger.warning(f"Invalid cert port: {parsed_url.port}")
        return False

    try:
        # Fetch or get cached cert
        if cert_url in CERT_CACHE:
            cert = CERT_CACHE[cert_url]
        else:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(cert_url)
                if res.status_code != 200:
                    logger.warning(f"Failed to fetch cert from Amazon: status {res.status_code}")
                    return False
                cert = x509.load_pem_x509_certificate(res.content)
                CERT_CACHE[cert_url] = cert

        # Verify cert validity period
        now = time.time()
        nvb = getattr(cert, "not_valid_before_utc", cert.not_valid_before).timestamp()
        nva = getattr(cert, "not_valid_after_utc", cert.not_valid_after).timestamp()
        if now < nvb or now > nva:
            logger.warning("Amazon certificate expired or not yet active")
            return False

        # Verify Subject Alternative Name contains echo.api.amazon.com
        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        if "echo.api.amazon.com" not in dns_names:
            logger.warning("SAN does not contain echo.api.amazon.com")
            return False

        # Verify signature (Amazon uses SHA256withRSA, with SHA1 fallback)
        public_key = cert.public_key()
        sig_bytes = base64.b64decode(signature)
        try:
            public_key.verify(
                sig_bytes,
                raw_body,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception:
            public_key.verify(
                sig_bytes,
                raw_body,
                padding.PKCS1v15(),
                hashes.SHA1()
            )
        return True
    except Exception as e:
        logger.warning(f"Signature verification failed: {e}")
        return False


def clean_query(q: str) -> str:
    """Removes common Alexa invocation artifacts from the query string."""
    patterns = [
        r"^(?:ask|tell)\s+youtube\s+music\s+to\s+play\s+",
        r"^youtube\s+music\s+play\s+",
        r"^play\s+",
        r"\s+on\s+youtube\s+music$",
        r"\s+by\s+youtube\s+music$",
        r"^starboyask\s+youtube\s+music\s+to\s+play\s+",
    ]
    cleaned = q.strip()
    for p in patterns:
        cleaned = re.sub(p, "", cleaned, flags=re.IGNORECASE).strip()
    return cleaned or q.strip()


def build_audio_directive(domain: str, play_behavior: str, video_id: str, title: str, artist: str, thumb_url: str, prev_token: Optional[str] = None):
    sec = generate_stream_token(video_id)
    stream_url = f"https://{domain}/stream/{video_id}?t={sec['token']}&exp={sec['exp']}"

    stream_obj = {
        "url": stream_url,
        "token": video_id,
        "offsetInMilliseconds": 0
    }
    if prev_token:
        stream_obj["expectedPreviousToken"] = prev_token

    metadata = {
        "title": title,
        "subtitle": artist
    }
    if thumb_url:
        metadata["art"] = {
            "sources": [{"url": thumb_url}]
        }

    return {
        "type": "AudioPlayer.Play",
        "playBehavior": play_behavior,
        "audioItem": {
            "stream": stream_obj,
            "metadata": metadata
        }
    }


def search_track(query: str):
    """Search for a track using YouTube Data API if key provided, else ytmusicapi."""
    clean_q = clean_query(query)
    logger.info(f"Searching YouTube Music for: '{clean_q}' (raw query: '{query}')")

    if YOUTUBE_API_KEY:
        try:
            logger.info("Using official YouTube Data API v3 for search")
            url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&q={quote(clean_q)}&type=video&maxResults=1&key={YOUTUBE_API_KEY}"
            resp = httpx.get(url, timeout=5.0)
            if resp.status_code == 200:
                items = resp.json().get("items", [])
                if items:
                    item = items[0]
                    vid = item.get("id", {}).get("videoId")
                    snippet = item.get("snippet", {})
                    title = snippet.get("title", "Unknown Track")
                    artist = snippet.get("channelTitle", "YouTube")
                    thumb_url = snippet.get("thumbnails", {}).get("high", {}).get("url", "")
                    if vid:
                        logger.info(f"Official API found track: '{title}' by '{artist}' (ID: {vid})")
                        return {"videoId": vid, "title": title, "artist": artist, "thumb": thumb_url}
        except Exception as e:
            logger.warning(f"YouTube Data API error: {e}; falling back to internal search")

    results = yt.search(clean_q, filter="songs")
    if not results:
        results = yt.search(clean_q)
    
    for r in results:
        # Look for a playable item with a videoId
        vid = r.get("videoId")
        if vid:
            title = r.get("title", "Unknown Track")
            artists = ", ".join([a.get("name", "") for a in r.get("artists", [])]) or "YouTube Music"
            thumbs = r.get("thumbnails", [])
            thumb_url = thumbs[-1]["url"] if thumbs else ""
            logger.info(f"Found track: '{title}' by '{artists}' (ID: {vid})")
            return {"videoId": vid, "title": title, "artist": artists, "thumb": thumb_url}
    return None


def get_radio_next(video_id: str):
    """Get the next recommended song in the radio queue."""
    try:
        watch = yt.get_watch_playlist(videoId=video_id, limit=5)
        tracks = watch.get("tracks", [])
        for t in tracks:
            vid = t.get("videoId")
            if vid and vid != video_id:
                title = t.get("title", "Next Track")
                artists = ", ".join([a.get("name", "") for a in t.get("artists", [])]) or "YouTube Music"
                thumbs = t.get("thumbnail", [])
                thumb_url = thumbs[-1]["url"] if thumbs else ""
                return {"videoId": vid, "title": title, "artist": artists, "thumb": thumb_url}
    except Exception as e:
        logger.error(f"Error fetching watch playlist: {e}")
    return None


import json
import traceback

@app.post("/alexa")
async def alexa_skill_handler(request: Request):
    domain = resolve_domain(request)
    raw_body = await request.body()

    if not await verify_alexa_request(request, raw_body):
        raise HTTPException(status_code=400, detail="Invalid request signature")

    try:
        data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception as e:
        logger.warning(f"Failed to decode JSON body: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    app_id = (
        data.get("session", {}).get("application", {}).get("applicationId")
        or data.get("context", {}).get("System", {}).get("application", {}).get("applicationId")
    )
    req = data.get("request", {})
    req_type = req.get("type", "Unknown")
    intent_name = req.get("intent", {}).get("name", "N/A") if req_type == "IntentRequest" else "N/A"
    logger.info(f"Incoming Alexa request: {req_type} (Intent: {intent_name}, AppId: {app_id})")

    # Validate Skill ID if set
    if ALEXA_SKILL_ID:
        clean_skill_id = ALEXA_SKILL_ID.strip()
        if not app_id or app_id.strip() != clean_skill_id:
            logger.warning(f"Skill ID mismatch: got '{app_id}', expected '{clean_skill_id}'")
            raise HTTPException(status_code=403, detail="Skill ID mismatch")

    # 1. LaunchRequest
    if req_type == "LaunchRequest":
        return {
            "version": "1.0",
            "response": {
                "outputSpeech": {
                    "type": "PlainText",
                    "text": "YouTube Music is ready. What would you like to hear?"
                },
                "shouldEndSession": False
            }
        }

    # 2. IntentRequest
    if req_type == "IntentRequest":
        intent = req.get("intent", {})
        intent_name = intent.get("name")

        if intent_name in ("PlayMusicIntent", "SearchIntent"):
            query_slot = intent.get("slots", {}).get("query", {}).get("value")
            if not query_slot:
                return {
                    "version": "1.0",
                    "response": {
                        "outputSpeech": {"type": "PlainText", "text": "What song or artist do you want to play?"},
                        "shouldEndSession": False
                    }
                }

            track = search_track(query_slot)
            if not track:
                return {
                    "version": "1.0",
                    "response": {
                        "outputSpeech": {"type": "PlainText", "text": f"Sorry, I couldn't find {query_slot} on YouTube Music."},
                        "shouldEndSession": True
                    }
                }

            directive = build_audio_directive(domain, "REPLACE_ALL", track["videoId"], track["title"], track["artist"], track["thumb"])
            return {
                "version": "1.0",
                "response": {
                    "outputSpeech": {
                        "type": "PlainText",
                        "text": f"Playing {track['title']} by {track['artist']}"
                    },
                    "directives": [directive]
                }
            }

        elif intent_name == "PlayLikedSongsIntent":
            try:
                liked = yt.get_liked_songs(limit=25)
                tracks = liked.get("tracks", [])
                if not tracks:
                    msg = "No liked songs found or cookie file is not configured."
                    return {"version": "1.0", "response": {"outputSpeech": {"type": "PlainText", "text": msg}, "shouldEndSession": True}}

                first = tracks[0]
                vid = first.get("videoId")
                title = first.get("title", "Liked Songs")
                artists = ", ".join([a.get("name", "") for a in first.get("artists", [])]) or "YouTube Music"
                thumbs = first.get("thumbnails", [])
                thumb_url = thumbs[-1]["url"] if thumbs else ""

                directive = build_audio_directive(domain, "REPLACE_ALL", vid, title, artists, thumb_url)
                return {
                    "version": "1.0",
                    "response": {
                        "outputSpeech": {"type": "PlainText", "text": "Playing your liked songs on YouTube Music."},
                        "directives": [directive]
                    }
                }
            except Exception as e:
                logger.error(f"Error fetching liked songs: {e}")
                return {
                    "version": "1.0",
                    "response": {
                        "outputSpeech": {"type": "PlainText", "text": "Could not access liked songs. Make sure browser.json is set up."},
                        "shouldEndSession": True
                    }
                }

        elif intent_name in ("AMAZON.PauseIntent", "AMAZON.StopIntent", "AMAZON.CancelIntent"):
            return {
                "version": "1.0",
                "response": {
                    "directives": [{"type": "AudioPlayer.Stop"}],
                    "shouldEndSession": True
                }
            }

        elif intent_name == "AMAZON.ResumeIntent":
            ap_ctx = data.get("context", {}).get("AudioPlayer", {})
            token = ap_ctx.get("token")
            offset = ap_ctx.get("offsetInMilliseconds", 0)
            if token:
                sec = generate_stream_token(token)
                stream_url = f"https://{domain}/stream/{token}?t={sec['token']}&exp={sec['exp']}"
                directive = {
                    "type": "AudioPlayer.Play",
                    "playBehavior": "REPLACE_ALL",
                    "audioItem": {
                        "stream": {
                            "url": stream_url,
                            "token": token,
                            "offsetInMilliseconds": offset
                        }
                    }
                }
                return {"version": "1.0", "response": {"directives": [directive]}}
            return {"version": "1.0", "response": {"shouldEndSession": True}}

        elif intent_name == "AMAZON.NextIntent":
            token = data.get("context", {}).get("AudioPlayer", {}).get("token")
            if token:
                nxt = get_radio_next(token)
                if nxt:
                    directive = build_audio_directive(domain, "REPLACE_ALL", nxt["videoId"], nxt["title"], nxt["artist"], nxt["thumb"])
                    return {
                        "version": "1.0",
                        "response": {
                            "directives": [directive]
                        }
                    }
            return {"version": "1.0", "response": {"directives": [{"type": "AudioPlayer.Stop"}], "shouldEndSession": True}}

        elif intent_name == "AMAZON.PreviousIntent":
            token = data.get("context", {}).get("AudioPlayer", {}).get("token")
            if token:
                sec = generate_stream_token(token)
                stream_url = f"https://{domain}/stream/{token}?t={sec['token']}&exp={sec['exp']}"
                directive = {
                    "type": "AudioPlayer.Play",
                    "playBehavior": "REPLACE_ALL",
                    "audioItem": {
                        "stream": {
                            "url": stream_url,
                            "token": token,
                            "offsetInMilliseconds": 0
                        }
                    }
                }
                return {"version": "1.0", "response": {"directives": [directive]}}
            return {"version": "1.0", "response": {"shouldEndSession": True}}

        elif intent_name in ("AMAZON.HelpIntent",):
            return {
                "version": "1.0",
                "response": {
                    "outputSpeech": {
                        "type": "PlainText",
                        "text": "You can say: play Bohemian Rhapsody, or play my liked songs."
                    },
                    "shouldEndSession": False
                }
            }

    # 3. AudioPlayer.PlaybackNearlyFinished -> Autoplay next track!
    if req_type == "AudioPlayer.PlaybackNearlyFinished":
        current_token = req.get("token")
        if current_token:
            nxt = get_radio_next(current_token)
            if nxt:
                directive = build_audio_directive(
                    domain,
                    "ENQUEUE",
                    nxt["videoId"],
                    nxt["title"],
                    nxt["artist"],
                    nxt["thumb"],
                    prev_token=current_token
                )
                return {
                    "version": "1.0",
                    "response": {
                        "directives": [directive]
                    }
                }

    # Default empty 200 response for lifecycle events (PlaybackStarted, PlaybackStopped, PlaybackFinished, SessionEndedRequest)
    return {"version": "1.0", "response": {}}


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        return Response(content=exc.detail, status_code=exc.status_code, media_type="text/plain")
    err_msg = traceback.format_exc()
    logger.error(f"Unhandled exception on {request.url.path}:\n{err_msg}")
    return Response(content=f"Error: {err_msg}", status_code=500, media_type="text/plain")


@app.get("/stream/{video_id}")
async def proxy_audio_stream(video_id: str, t: str, exp: str, request: Request):
    """Securely proxies YouTube audio stream directly to Alexa with range support."""
    if not re.fullmatch(r"^[a-zA-Z0-9_-]{11}$", video_id):
        raise HTTPException(status_code=400, detail="Invalid video ID format")

    if not verify_stream_token(video_id, t, exp):
        raise HTTPException(status_code=403, detail="Forbidden: Invalid or expired audio token")

    audio_url = None

    # 1. First attempt: resolve via ytmusicapi get_song (uses internal mobile endpoint, no datacenter block)
    try:
        logger.info(f"Resolving audio stream for {video_id} via ytmusicapi")
        song_data = yt.get_song(video_id)
        streaming_data = song_data.get("streamingData", {})
        formats = streaming_data.get("adaptiveFormats", [])
        for f in formats:
            if "audio/mp4" in f.get("mimeType", "") and f.get("url"):
                audio_url = f.get("url")
                logger.info(f"Resolved direct audio/mp4 stream from ytmusicapi for {video_id}")
                break
        if not audio_url:
            for f in formats:
                if "audio" in f.get("mimeType", "") and f.get("url"):
                    audio_url = f.get("url")
                    logger.info(f"Resolved fallback audio stream from ytmusicapi for {video_id}")
                    break
    except Exception as e:
        logger.warning(f"ytmusicapi get_song failed for {video_id}: {e}")

    # 2. Fallback to yt-dlp if direct URL was not available
    if not audio_url:
        has_cookies = os.path.exists(COOKIE_FILE) and os.path.getsize(COOKIE_FILE) > 50
        if has_cookies:
            ydl_opts = {
                "format": "140/bestaudio[ext=m4a]/bestaudio[acodec^=mp4a]/bestaudio/best",
                "quiet": True,
                "no_warnings": True,
                "noplaylist": True,
                "cookiefile": COOKIE_FILE,
                "extractor_args": {
                    "youtube": {
                        "player_client": ["web", "mweb", "tv"]
                    }
                },
            }
            logger.info(f"Using cookiefile {COOKIE_FILE} with [web, mweb, tv] client for stream extraction")
        else:
            ydl_opts = {
                "format": "140/bestaudio[ext=m4a]/bestaudio[acodec^=mp4a]/bestaudio/best",
                "quiet": True,
                "no_warnings": True,
                "noplaylist": True,
                "extractor_args": {
                    "youtube": {
                        "player_client": ["tv_embedded", "tv", "android", "mweb"]
                    }
                },
            }
            logger.info("No cookies found: using [tv_embedded, tv, android] client for stream extraction")

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(f"https://www.youtube.com/watch?v={video_id}", download=False)
                audio_url = info.get("url")
        except Exception as e:
            logger.error(f"yt-dlp resolution error for {video_id}: {traceback.format_exc()}")

    if not audio_url:
        raise HTTPException(status_code=404, detail="Audio stream not found")

    # Forward range header from Alexa
    client = httpx.AsyncClient(follow_redirects=True, timeout=30.0)
    req_headers = {}
    range_header = request.headers.get("Range")
    if range_header:
        req_headers["Range"] = range_header

    upstream_req = client.build_request("GET", audio_url, headers=req_headers)
    upstream_resp = await client.send(upstream_req, stream=True)

    resp_headers = {
        "Content-Type": upstream_resp.headers.get("Content-Type", "audio/mp4"),
        "Accept-Ranges": "bytes",
    }
    if "Content-Length" in upstream_resp.headers:
        resp_headers["Content-Length"] = upstream_resp.headers["Content-Length"]
    if "Content-Range" in upstream_resp.headers:
        resp_headers["Content-Range"] = upstream_resp.headers["Content-Range"]

    async def stream_generator():
        try:
            async for chunk in upstream_resp.aiter_bytes():
                yield chunk
        finally:
            await upstream_resp.aclose()
            await client.aclose()

    return StreamingResponse(
        stream_generator(),
        status_code=upstream_resp.status_code,
        headers=resp_headers
    )


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "alexa-ytm"}

