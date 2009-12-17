//////////////////////////////////////////////////////////////////////////////
//
// Open Remote Play
// http://ps3-hacks.com
//
//////////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but 
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//
//////////////////////////////////////////////////////////////////////////////

#include <iostream>
#include <sstream>
#include <vector>
#include <queue>

#include "orp.h"
#include "base64.h"
#include "images.h"
#include "font.h"

static void orpOutput(const char *format, va_list ap)
{
	static SDL_mutex *lock = NULL;
	if (lock == NULL) lock = SDL_CreateMutex();
	SDL_LockMutex(lock);
	static FILE *log = NULL;
	if (!log) {
		log = fopen("orp.log", "w");
		if (log) fprintf(log, "Open Remote Play v%s\n", ORP_VERSION);
	}
	if (log) {
		fprintf(log, "%10u: ", SDL_GetTicks());
		vfprintf(log, format, ap);
		fflush(log);
	}
#ifndef _WIN32
	vfprintf(stderr, format, ap);
#endif
	SDL_UnlockMutex(lock);
}

static void orpPrintf(const char *format, ...)
{
	static SDL_mutex *lock = NULL;
	if (lock == NULL) lock = SDL_CreateMutex();
	SDL_LockMutex(lock);
	va_list ap;
	va_start(ap, format);
	orpOutput(format, ap);
	va_end(ap);
	SDL_UnlockMutex(lock);
}

static Sint32 orpCurlDebug(CURL *curl, curl_infotype type, char *text, size_t text_len, void *data)
{
	static SDL_mutex *lock = NULL;
	if (lock == NULL) lock = SDL_CreateMutex();
	SDL_LockMutex(lock);
	ostringstream os;
	char *url = NULL;
	curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
	if (url != NULL) os << url << ": ";
	else os << "<Unknown>: ";
	switch (type) {
	case CURLINFO_TEXT:
		break;
	case CURLINFO_HEADER_IN:
		os << ">> ";
		break;
	case CURLINFO_HEADER_OUT:
		os << "<< Sending headers:" << endl;
		break;
	case CURLINFO_DATA_IN:
		SDL_UnlockMutex(lock);
		return 0;
	case CURLINFO_DATA_OUT:
		SDL_UnlockMutex(lock);
		return 0;
	}
	char *buffer = new char[text_len + 1];
	memset(buffer, 0, text_len + 1);
	memcpy(buffer, text, text_len);
	if (buffer[text_len -1] == '\n')
		os << buffer;
	else
		os << buffer << endl;
	delete [] buffer;
	orpPrintf(os.str().c_str());
	SDL_UnlockMutex(lock);
	return 0;
}

static void orpAVDebug(void *ptr, Sint32 level, const char *format, va_list ap)
{
	orpOutput(format, ap);
}

static struct orpHeader_t orpHeaderList[] = {
	{ HEADER_APP_REASON, "PREMO-Application-Reason" },
	{ HEADER_AUDIO_BITRATE, "PREMO-Audio-Bitrate" },
	{ HEADER_AUDIO_BITRATE_ABILITY, "PREMO-Audio-Bitrate-Ability" },
	{ HEADER_AUDIO_CHANNELS, "PREMO-Audio-Channels" },
	{ HEADER_AUDIO_CLOCKFREQ, "PREMO-Audio-ClockFrequency" },
	{ HEADER_AUDIO_CODEC, "PREMO-Audio-Codec" },
	{ HEADER_AUDIO_CONFIG, "PREMO-Audio-Config" },
	{ HEADER_AUDIO_SAMPLERATE, "PREMO-Audio-SamplingRate" },
	{ HEADER_AUTH, "PREMO-Auth" },
	{ HEADER_CTRL_BITRATE, "Bitrate" },
	{ HEADER_CTRL_MAXBITRATE, "Max-Bitrate" },
	{ HEADER_CTRL_MODE, "Mode" },
	{ HEADER_EXEC_MODE, "PREMO-Exec-Mode" },
	{ HEADER_MODE, "PREMO-Mode" },
	{ HEADER_NONCE, "PREMO-Nonce" },
	{ HEADER_OTA, "PREMO-OTA" },
	{ HEADER_PAD_ASSIGN, "PREMO-Pad-Assign" },
	{ HEADER_PAD_COMPLETE, "PREMO-Pad-Complete" },
	{ HEADER_PAD_INDEX, "PREMO-Pad-Index" },
	{ HEADER_PAD_INFO, "PREMO-Pad-Info" },
	{ HEADER_PLATFORM_INFO, "PREMO-Platform-Info" },
	{ HEADER_POWER_CONTROL, "PREMO-Power-Control" },
	{ HEADER_PS3_NICKNAME, "PREMO-PS3-Nickname" },
	{ HEADER_PSPID, "PREMO-PSPID" },
	{ HEADER_TRANS, "PREMO-Trans" },
	{ HEADER_TRANS_MODE, "PREMO-Trans-Mode" },
	{ HEADER_SESSIONID, "SessionID" },
	{ HEADER_SIGNINID, "PREMO-SIGNIN-ID" },
	{ HEADER_USERNAME, "PREMO-UserName" },
	{ HEADER_VERSION, "PREMO-Version" },
	{ HEADER_VIDEO_BITRATE, "PREMO-Video-Bitrate" },
	{ HEADER_VIDEO_BITRATE_ABILITY, "PREMO-Video-Bitrate-Ability" },
	{ HEADER_VIDEO_CLOCKFREQ, "PREMO-Video-ClockFrequency" },
	{ HEADER_VIDEO_CODEC, "PREMO-Video-Codec" },
	{ HEADER_VIDEO_CONFIG, "PREMO-Video-Config" },
	{ HEADER_VIDEO_FRAMERATE, "PREMO-Video-Framerate" },
	{ HEADER_VIDEO_FRAMERATE_ABILITY, "PREMO-Video-Framerate-Ability" },
	{ HEADER_VIDEO_OUT_CTRL, "PREMO-VideoOut-Ctrl" },
	{ HEADER_VIDEO_RESOLUTION, "PREMO-Video-Resolution" },
	{ HEADER_VIDEO_RESOLUTION_ABILITY, "PREMO-Video-Resolution-Ability" },

	{ HEADER_NULL, "null" },
};

static const char *orpGetHeader(enum orpHeader header)
{
	Uint32 i;
	for (i = 0; orpHeaderList[i].header != HEADER_NULL; i++) {
		if (orpHeaderList[i].header != header) continue;
		return orpHeaderList[i].name.c_str();
	}
	return orpHeaderList[HEADER_NULL].name.c_str();
}

static const char *orpGetHeaderValue(enum orpHeader header, vector<struct orpHeaderValue_t *> &headerList)
{
	Uint32 i;
	for (i = 0; headerList[i]->header != HEADER_NULL; i++) {
		if (headerList[i]->header != header) continue;
		return headerList[i]->value.c_str();
	}
	return NULL;
}

static struct orpCtrlMode_t orpCtrlList[] = {
	{ CTRL_CHANGE_BITRATE, "change-bitrate" },
	{ CTRL_SESSION_TERM, "session-term" },

	{ CTRL_NULL, "null" }
};

static void orpPostEvent(enum orpEvent id)
{
	SDL_Event event;

	event.type = SDL_USEREVENT;
	event.user.code = id;
	event.user.data1 = NULL;
	event.user.data2 = NULL;

	SDL_PushEvent(&event);
}

static void orpPostError(const char *text)
{
	SDL_Event event;

	event.type = SDL_USEREVENT;
	event.user.code = EVENT_ERROR;
	event.user.data1 = strdup(text);
	event.user.data2 = NULL;

	SDL_PushEvent(&event);
}

static size_t orpParseResponseHeader(void *ptr, size_t size, size_t nmemb, void *stream)
{
	Uint8 *data = (Uint8 *)ptr;
	Uint32 len = (Uint32)(size * nmemb);
	vector<struct orpHeaderValue_t *> *headerList = (vector<struct orpHeaderValue_t *> *)stream;

	Uint32 i;
	ostringstream h, v;
	for (i = 0; i < len; i++) {
		if (data[i] == (Uint8)' ' || data[i] == (Uint8)'\t' ||
			data[i] == (Uint8)'\n' || data[i] == (Uint8)'\r') continue;
		else if (data[i] == (Uint8)':') break;
		h << (char)data[i];
	}

	// Headers received...
	if (h.str().length() == 0) return (size_t)len;

	for (++i; i < len; i++) {
		if (data[i] == (Uint8)' ' || data[i] == (Uint8)'\t' ||
			data[i] == (Uint8)'\n' || data[i] == (Uint8)'\r') continue;
		v << (char)data[i];
	}

	for (i = 0; orpHeaderList[i].header != HEADER_NULL; i++) {
		if (strcasecmp(orpHeaderList[i].name.c_str(), h.str().c_str())) continue;
		struct orpHeaderValue_t *header = new struct orpHeaderValue_t;
		header->header = orpHeaderList[i].header;
		header->value = v.str();
		headerList->push_back(header);
	}

	return (size_t)len;
}

static size_t orpParseStreamData(void *ptr, size_t size, size_t nmemb, void *_stream)
{
	Uint8 *data = (Uint8 *)ptr;
	Uint32 len = (Uint32)(size * nmemb);
	orpStreamBase *stream = (orpStreamBase *)_stream;
	orpStreamBuffer *sb = stream->GetBuffer();

#ifdef ORP_DUMP_STREAM_RAW
	fwrite(data, 1, len, _config->h_raw);
#endif

	// Allocate frame buffer
	Uint8 *buffer = new Uint8[sb->len + len];
	if (!buffer) {
		orpPostError("Memory allocation error!");
		return 0;
	}
	Uint8 *bp = buffer;

	// Prepend stored chunk if present
	if (sb->len) {
		memcpy(bp, sb->data, sb->len);
		memcpy(bp + sb->len, data, len);
		len += sb->len;
		delete [] sb->data;
		sb->len = 0;
	} else memcpy(bp, data, len);

	// Eat 0x0d 0x0a prefix if present
	if (len >= 1 && bp[0] == 0x0d) {
		len--; bp++;
	}
	if (len >= 1 && bp[0] == 0x0a) {
		len--; bp++;
	}

	// Need at least 8 bytes (XXXXXX\n\r) to continue
	if (len < 8) {
		sb->len = len;
		sb->data = new Uint8[len];
		if (!sb->data) {
			delete [] buffer;
			orpPostError("Memory allocation error!");
			return 0;
		}
		memcpy(sb->data, bp, len);
		delete [] buffer;
		return (size * nmemb);
	}

	// Expected trailing 0xd 0xa not found!
	if (bp[6] != 0x0d || bp[7] != 0x0a) {
		delete [] buffer;
		orpPostError("Unexpected data!");
		return 0;
	}

	// Zero out first byte after chunk length (for sscanf)
	bp[6] = 0x00;
	Uint32 chunk_len = 0;

	// Extract chunk length
	if (sscanf((const char *)bp, "%06x", &chunk_len) != 1) {
		delete [] buffer;
		orpPostError("Missing chunk size!");
		return 0;
	}

	// Remove chunk length; advance buffer, decrement length
	len -= 8; bp += 8;

	// Available data less than what we need?
	if (len < chunk_len) {
		// Undo buffer and length adjustments for next packet
		len += 8; bp -= 8;
		bp[6] = 0x0d;

		// Allocate memory to hold partial packet
		sb->len = len;
		sb->data = new Uint8[len];
		if (!sb->data) {
			delete [] buffer;
			orpPostError("Memory allocation error!");
			return 0;
		}
		memcpy(sb->data, bp, len);
		delete [] buffer;

		// Next...
		return (size * nmemb);

	} else if (len > chunk_len && len - chunk_len == 2 &&
		*(bp + chunk_len) == 0x0d && *(bp + chunk_len + 1) == 0x0a) {
		// Don't stash trailing 0xd 0xa...

	// More data available than we need?
	} else if (len > chunk_len) {
		// Save the overflow for next call...
		sb->len = len - chunk_len;
		sb->data = new Uint8[sb->len];
		if (!sb->data) {
			delete [] buffer;
			orpPostError("Memory allocation error!");
			return 0;
		}
		memcpy(sb->data, bp + chunk_len, sb->len);
	}

	// We have a full audio/video packet (frame)
	if (bp[0] != 0x80) {
		orpPrintf("%s: invalid packet header\n", stream->GetCodecName());
		orpPostError("Invalid packet header!");
		delete [] buffer;
		return 0;
	}

	// Asked to restore audio/video stream?
	if (bp[1] == 0xfd) {
		orpPrintf("%s: restore (reset)\n", stream->GetCodecName());
		orpPostEvent(EVENT_RESTORE);
		delete [] buffer;
		return (size * nmemb);
	}

	// Audio/video magic of 0x8081 seems to mean PS3 shutdown
	if (bp[1] == 0x81) {
		orpPrintf("%s: system power-off\n", stream->GetCodecName());
		orpPostEvent(EVENT_SHUTDOWN);
		delete [] buffer;
		return (size * nmemb);
	}

#ifdef ORP_DUMP_STREAM_HEADER
	fwrite(bp, 1, sizeof(orpStreamPacketHeader_t), _config->h_header);
#endif

	// Audio or video header?
	if (bp[1] != 0x80 && bp[1] != 0xff && bp[1] != 0xfb && bp[1] != 0xfc &&
		bp[1] != 0xfe) {
		orpPrintf("%s: invalid magic: 0x%02x%02x\n", stream->GetCodecName(),
			bp[0], bp[1]);
		delete [] buffer;
		// Discard...
		return (size * nmemb);
	}

	// Allocate new packet
	struct orpStreamPacket_t *packet = new struct orpStreamPacket_t;
	if (!packet) {
		delete [] buffer;
		orpPostError("Memory allocation error!");
		return 0;
	}

	// Copy header, set length
	memcpy(&packet->header, bp, sizeof(struct orpStreamPacketHeader_t));
	memset(&packet->pkt, 0, sizeof(AVPacket));
	packet->pkt.size = chunk_len - sizeof(struct orpStreamPacketHeader_t);

	// Header size must match packet length
	if (packet->pkt.size != SDL_Swap16(packet->header.len)) {
//		FILE *fh = fopen("bad-header.dat", "w+");
//		if (fh) {
//			fwrite(&packet->header, 1, sizeof(orpStreamPacketHeader_t), fh);
//			fclose(fh);
//		}
		orpPrintf("%s: packet length mis-match: %u, expected: %u\n",
			stream->GetCodecName(), packet->pkt.size,
			SDL_Swap16(packet->header.len));

		// TODO: For now we just accept the header length over the
		// chunk size.  This only seems to happen with MPEG4 video, ex:
		// PixelJunk Monsers/Eden
		packet->pkt.size = SDL_Swap16(packet->header.len);
	}

	// Allocate payload
	packet->pkt.data = new Uint8[packet->pkt.size +
		FF_INPUT_BUFFER_PADDING_SIZE];
	if (!packet->pkt.data) {
		delete packet;
		delete [] buffer;
		orpPostError("Memory allocation error!");
		return 0;
	}
	memset(packet->pkt.data + packet->pkt.size, 0,
		FF_INPUT_BUFFER_PADDING_SIZE);

	// Copy payload
	bp += sizeof(struct orpStreamPacketHeader_t);
	memcpy(packet->pkt.data, bp, packet->pkt.size);
	delete [] buffer;

	bool video_key_frame = false;
	struct orpKey_t *key = stream->GetKeys();
#if 1
	// Decrypt h2.64 video key-frames
	if ((packet->header.magic[1] == 0xff || packet->header.magic[1] == 0xfe)
		&& packet->header.unk6 == 0x0401) {
		video_key_frame = true;
		memcpy(key->iv1, key->xor_nonce, ORP_KEY_LEN);
		AES_cbc_encrypt(packet->pkt.data, packet->pkt.data,
			packet->pkt.size - (packet->pkt.size % ORP_KEY_LEN),
			stream->GetDecryptKey(), key->iv1, AES_DECRYPT);

		if (packet->pkt.data[0] != 0x00) {
			orpPrintf("%s: packet decryption failure: 0x%02x.\n",
				stream->GetCodecName(), packet->pkt.data[0]);
#ifdef ORP_DUMP_STREAM_DATA
			fwrite(bp, 1, packet->pkt.size, _config->h_data);
#endif
			delete [] packet->pkt.data;
			delete packet;
			orpPostError("Corrupt video stream!");
			return 0;
		}
	}
	// Decrypt AAC audio
	else if (packet->header.magic[1] == 0x80 && packet->header.unk8) {
		memcpy(key->iv1, key->xor_nonce, ORP_KEY_LEN);
		AES_cbc_encrypt(packet->pkt.data, packet->pkt.data,
			packet->pkt.size - (packet->pkt.size % ORP_KEY_LEN),
			stream->GetDecryptKey(), key->iv1, AES_DECRYPT);
	}
	// Decrypt MPEG4 video key-frames
	else if (packet->header.magic[1] == 0xfb && (
		packet->header.unk6 == 0x0001 || packet->header.unk6 == 0x0401)) {
		video_key_frame = true;
		memcpy(key->iv1, key->xor_nonce, ORP_KEY_LEN);
		AES_cbc_encrypt(packet->pkt.data, packet->pkt.data,
			packet->pkt.size - (packet->pkt.size % ORP_KEY_LEN),
			stream->GetDecryptKey(), key->iv1, AES_DECRYPT);
	}
	// Decrypt ATRAC3 audio
	else if (packet->header.magic[1] == 0xfc && packet->header.unk8) {
		memcpy(key->iv1,
			key->xor_nonce, ORP_KEY_LEN);
		AES_cbc_encrypt(packet->pkt.data, packet->pkt.data,
			packet->pkt.size - (packet->pkt.size % ORP_KEY_LEN),
			stream->GetDecryptKey(), key->iv1, AES_DECRYPT);
	}
#ifdef ORP_DUMP_STREAM_DATA
	fwrite(packet->pkt.data, 1, packet->pkt.size, _config->h_data);
#endif
#endif
	packet->clock = SDL_Swap32(packet->header.clock);

	// Push stream packet
	Uint32 vc, ac; //, duration;
	if (stream->GetType() == ST_VIDEO) {
#if 0
		stream->GetBuffer()->GetDuration(duration);
		if (duration == 0 && !video_key_frame) {
			orpPrintf("discarding video frame: video buffer empty and not a key frame.\n");
			delete [] packet->pkt.data;
			delete packet;
			return (size * nmemb);
		}
#endif
		stream->GetSiblingClock(ac);
		if (ac != 0 && ac < stream->GetClock(vc)) {
			double v = (double)vc / (double)stream->GetClockFrequency();
			double a = (double)ac / (double)stream->GetSibling()->GetClockFrequency();
			Uint32 delay = (Uint32)((v - a) * 1000.0);
			//orpPrintf("video clock ahead by: %.02fs, delay: %u\n", v - a, delay / 2);
			SDL_Delay(delay);
		}
	}
	else {
#if 0
		if (stream->GetSibling()->GetBuffer()->GetDuration(duration) == 0) {
			SDL_PauseAudio(1);
			orpPrintf("discarding audio frame: video buffer empty.\n");
			delete [] packet->pkt.data;
			delete packet;
			return (size * nmemb);
		}
		if (stream->GetBuffer()->IsBufferReady()) SDL_PauseAudio(0);
		stream->GetSiblingClock(vc);
		if (packet->clock < vc) {
			//orpPrintf("discarding audio frame: older than last video frame.\n");
			delete [] packet->pkt.data;
			delete packet;
			return (size * nmemb);
		}
#endif
	}
	sb->Push(stream, packet);

	return (size * nmemb);
}

static bool orpDecodeKey(Uint8 *dst, const string &src)
{
	Base64 base64;
	Uint8 *result = base64.Decode((const Uint8 *)src.c_str());
	if (!result) return false;
	memcpy(dst, result, ORP_KEY_LEN);
	delete [] result;
	return true;
}

static SDL_mutex *orpGlobalMutex = NULL;

static Sint32 orpThreadVideoDecode(void *_stream)
{
	orpStreamVideo *stream = (orpStreamVideo *)_stream;
	orpStreamBuffer *buffer = stream->GetBuffer();
	struct orpView_t *view = stream->GetView();
	Sint32 bytes_decoded, frame_done = 0;
	Uint32 delay = 0, decode = 0;
	Uint32 last_clock = 0;
	Uint32 clock_freq = stream->GetClockFrequency();

	AVFrame *frame = avcodec_alloc_frame();
	if (!frame) {
		orpPrintf("Error allocating AVFrame.\n");
		return -1;
	}

	while (!stream->ShouldTerminate()) {
		if (buffer->WaitOnBuffer() != 0) {
			orpPrintf("Error waiting on video buffer.\n");
			return -1;
		}
		while (!stream->ShouldTerminate()) {
			Uint32 ticks = SDL_GetTicks();
			struct orpStreamPacket_t *packet = buffer->Pop();
			if (!packet) break;

			if (last_clock != 0) {
				Uint32 interval = packet->clock - last_clock;
				if (interval > 0) {
					double diff = (double)interval / (double)clock_freq;
					delay = (Uint32)(diff * (double)1000) - decode;
					if ((Sint32)delay > 0) SDL_Delay(delay);
				}
			}

			bytes_decoded = avcodec_decode_video2(
				stream->GetContext(),
				frame, &frame_done, &packet->pkt);

			if (bytes_decoded != -1 && frame_done) {
				SDL_LockMutex(view->lock);
				if (!view->overlay) {
					SDL_UnlockMutex(view->lock);
					return -1;
				}
				SDL_LockYUVOverlay(view->overlay);

				stream->ScaleFrame(frame);

				SDL_Rect rect;
				rect.x = 0;
				if (view->size == VIEW_FULLSCREEN) {
					rect.y = view->fs.y;
					rect.w = view->fs.w;
					rect.h = view->fs.h;
				} else {
					rect.y = 0;
					rect.w = view->scale.w;
					rect.h = view->scale.h;
				}

				if (view->status_sticky ||
					view->status_ticks >= SDL_GetTicks()) {
					SDL_Rect src, dst;
					src.x = src.y = 0;
					src.w = view->status_bg->w;
					src.h = view->status_bg->h;
					dst.x = 0;
					dst.y = rect.h - view->status_bg->h;
					dst.w = view->status_bg->w;
					dst.h = view->status_bg->h;
					SDL_BlitOverlay(view->status_yuv, &src,
						view->overlay, &dst);
				}

				SDL_DisplayYUVOverlay(view->overlay, &rect);
				SDL_UnlockMutex(view->lock);
			}

			last_clock = packet->clock;
			delete [] packet->pkt.data;
			delete packet;

			decode = SDL_GetTicks() - ticks;
			if ((Sint32)delay > 0) decode -= delay;
		}
	}

	orpPrintf("Exit video decode thread.\n");
	return 0;
}

static Sint32 orpThreadVideoConnection(void *_stream)
{
	orpStreamVideo *stream = (orpStreamVideo *)_stream;

	CURL *curl = curl_easy_init();

	curl_easy_setopt(curl, CURLOPT_URL, stream->GetUrl());
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, orpCurlDebug);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, ORP_USER_AGENT);

	vector<struct orpHeaderValue_t *> headerList;
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&headerList);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, orpParseResponseHeader);

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, _stream);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, orpParseStreamData);

	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0);
	curl_easy_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0);

	struct curl_slist *headers = NULL;

	ostringstream os;
	os << "Host:";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Accept: */*;q=0.01";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Accept-Encoding:\"\"";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Accept-Charset: iso-8859-1;q=0.01";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Host: " << stream->GetHost() << ":" << stream->GetPort();
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << orpGetHeader(HEADER_VIDEO_CODEC);
	os << ": " << stream->GetCodecName();
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << orpGetHeader(HEADER_VIDEO_RESOLUTION);
	os << ": " << ORP_FRAME_WIDTH << "x" << ORP_FRAME_HEIGHT;
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << orpGetHeader(HEADER_AUTH);
	os << ": " << stream->GetAuthKey();
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << orpGetHeader(HEADER_SESSIONID);
	os << ": " << stream->GetSessionId();
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Connection: Keep-Alive";
	headers = curl_slist_append(headers, os.str().c_str());

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	CURLcode cc;
		
	cc = curl_easy_perform(curl);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	orpPrintf("%s: stream exit: %d\n", stream->GetCodecName(), cc);
	orpPostEvent(EVENT_STREAM_EXIT);

	return 0;
}

static void orpCallbackAudioDecode(void *_stream, Uint8 *audio, int req_len)
{
	orpStreamAudio *stream = (orpStreamAudio *)_stream;
	orpStreamBuffer *buffer = stream->GetBuffer();

	struct orpStreamPacket_t *packet = buffer->Pop();
	if (!packet) {
		memset(audio, 0, req_len);
		return;
	}

	Sint32 bytes_decoded, frame_size;
	Uint8 frame[(AVCODEC_MAX_AUDIO_FRAME_SIZE * 3) / 2];

	frame_size = sizeof(frame);
	bytes_decoded = avcodec_decode_audio3(stream->GetContext(),
		(Sint16 *)frame, &frame_size, &packet->pkt);
	if (bytes_decoded != -1 && frame_size) {
		memcpy(audio, frame, req_len);
		if (frame_size != req_len) {
			orpPrintf("%s: requested: %u, supplied: %u\n",
				stream->GetCodecName(), req_len, frame_size);
		}	
	} else memset(audio, 0, req_len);

	delete [] packet->pkt.data;
	delete packet;
}

static Sint32 orpThreadAudioConnection(void *_stream)
{
	orpStreamAudio *stream = (orpStreamAudio *)_stream;

	CURL *curl = curl_easy_init();

	curl_easy_setopt(curl, CURLOPT_URL, stream->GetUrl());
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, orpCurlDebug);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, ORP_USER_AGENT);

	vector<struct orpHeaderValue_t *> headerList;
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&headerList);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, orpParseResponseHeader);

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, _stream);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, orpParseStreamData);

	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0);
	curl_easy_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0);

	struct curl_slist *headers = NULL;

	ostringstream os;
	os << "Host:";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Accept: */*;q=0.01";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Accept-Encoding:\"\"";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Accept-Charset: iso-8859-1;q=0.01";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Host: " << stream->GetHost() << ":" << stream->GetPort();
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << orpGetHeader(HEADER_AUDIO_CODEC);
	os << ": " << stream->GetCodecName();
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << orpGetHeader(HEADER_AUDIO_BITRATE);
	//os << ": " << "128000";
	os << ": " << "576000";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << orpGetHeader(HEADER_AUTH);
	os << ": " << stream->GetAuthKey();
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << orpGetHeader(HEADER_SESSIONID);
	os << ": " << stream->GetSessionId();
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Connection: Keep-Alive";
	headers = curl_slist_append(headers, os.str().c_str());

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	CURLcode cc;
		
	cc = curl_easy_perform(curl);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	orpPrintf("%s: stream exit: %d\n", stream->GetCodecName(), cc);
	orpPostEvent(EVENT_STREAM_EXIT);

	return 0;
}

orpStreamBuffer::orpStreamBuffer()
	: clock(0), base(0), lock(NULL), period(90000),
	len(0), pos(0), data(NULL), sibling(NULL)
{
	lock = SDL_CreateMutex();
	cond_buffer_ready = SDL_CreateCond();
	lock_buffer_ready = SDL_CreateMutex();
}

orpStreamBuffer::~orpStreamBuffer()
{
	if (lock) SDL_DestroyMutex(lock);
	if (cond_buffer_ready) SDL_DestroyCond(cond_buffer_ready);
}

void orpStreamBuffer::Push(orpStreamBase *stream, struct orpStreamPacket_t *packet)
{
	static Uint32 ac = 0, vc = 0, ad = 0, vd = 0, acf = 0, vcf = 0;
	if (stream->GetType() == ST_AUDIO) {
		ac = packet->clock;
		GetDuration(ad);
		stream->GetSiblingClock(vc);
		stream->GetSiblingDuration(vd);
		if (acf == 0) acf = stream->GetClockFrequency();
		if (vcf == 0) vcf = stream->GetSibling()->GetClockFrequency();
	} else {
		vc = packet->clock;
		GetDuration(vd);
		stream->GetSiblingClock(ac);
		stream->GetSiblingDuration(ad);
		if (vcf == 0) vcf = stream->GetClockFrequency();
		if (acf == 0) acf = stream->GetSibling()->GetClockFrequency();
	}
	double a = (double)ac / (double)acf;
	double v = (double)vc / (double)vcf;
	orpPrintf("Stream: A: %5.1f V: %5.1f A-V: %7.03f\r",
		a, v, a - v);

	SDL_LockMutex(lock);

	pkt.push(packet);
	clock = packet->clock;
	duration = UpdateDuration();
	SDL_CondSignal(cond_buffer_ready);

	SDL_UnlockMutex(lock);
}

struct orpStreamPacket_t *orpStreamBuffer::Pop(void)
{
	orpStreamPacket_t *packet = NULL;

	SDL_LockMutex(lock);

	if (pkt.size()) {
		packet = pkt.front();
		pkt.pop();
	}

	UpdateDuration();
	SDL_UnlockMutex(lock);

	return packet;
}

Uint32 orpStreamBuffer::GetClock(Uint32 &clock)
{
	SDL_LockMutex(lock);
	clock = this->clock;
	SDL_UnlockMutex(lock);
	return clock;
}

Uint32 orpStreamBuffer::GetDuration(Uint32 &duration)
{
	SDL_LockMutex(lock);
	duration = this->duration;
	SDL_UnlockMutex(lock);
	return duration;
}

Uint32 orpStreamBuffer::UpdateDuration(void)
{
	if (pkt.size() < 2)
		duration = 0;
	else
		duration = pkt.back()->clock - pkt.front()->clock;
	return duration;
}

orpStreamBase::orpStreamBase(orpStreamType type, struct orpCodec_t *codec)
	: type(type), codec(codec), clock_freq(0), sibling(NULL),
	thread_connection(NULL)
{
	memset(&key, 0, sizeof(struct orpKey_t));
	buffer = new orpStreamBuffer();
}

orpStreamBase::~orpStreamBase()
{
	Sint32 thread_result;
	if (thread_connection)
		SDL_WaitThread(thread_connection, &thread_result);
	delete buffer;
}

void orpStreamBase::SetKeys(const struct orpKey_t *key)
{
	memcpy(&this->key, key, sizeof(struct orpKey_t));
	AES_set_decrypt_key(this->key.xor_pkey, ORP_KEY_LEN * 8,
		&aes_key);
}

const char *orpStreamBase::GetAuthKey(enum orpAuthType type)
{
	switch (type) {
	case orpAUTH_CHANGE_BITRATE:
		return (const char *)key.auth_change_bitrate;
	case orpAUTH_SESSION_TERM:
		return (const char *)key.auth_session_term;
	}
	return (const char *)key.auth_normal;
}

Sint32 orpStreamBase::Connect(string host, Uint16 port, string url, string session_id)
{
	this->host = host;
	this->port = port;
	this->url = url;
	this->session_id = session_id;
	return 0;
}

orpStreamAudio::orpStreamAudio(struct orpCodec_t *codec)
	: orpStreamBase(ST_AUDIO, codec),
	channels(0), sample_rate(0), bit_rate(0), context(NULL)
{
}

orpStreamAudio::~orpStreamAudio()
{
	CloseDevice();
	CloseDecoder();
}

Sint32 orpStreamAudio::InitDevice(void)
{
	SDL_AudioSpec spec, req_spec;
	req_spec.freq = sample_rate;
	req_spec.format = AUDIO_S16SYS;
	req_spec.channels = channels;
	req_spec.silence = 0;
	req_spec.samples = ORP_AUDIO_BUF_LEN;
	req_spec.callback = orpCallbackAudioDecode;
	req_spec.userdata = (void *)this;

	if(SDL_OpenAudio(&req_spec, &spec) == -1) {
		orpPrintf("SDL_OpenAudio: %s\n", SDL_GetError());
		return -1;
	}

	SDL_PauseAudio(0);

	return 0;
}

Sint32 orpStreamAudio::InitDecoder(void)
{
	SDL_LockMutex(orpGlobalMutex);
	context = avcodec_alloc_context();
	context->channels = channels;
	context->sample_rate = sample_rate;
	if (codec->codec->id == CODEC_ID_ATRAC3) {
		struct atrac3_config_t {
			Uint16 unk0;	// 2
			Uint32 unk1;	// 6
			Uint16 unk2;	// 8
			Uint16 unk3;	// 10
			Uint16 unk4;	// 12
			Uint16 unk5;	// 14
		};
		struct atrac3_config_t *at3_config;
		at3_config = (struct atrac3_config_t *)av_malloc(sizeof(struct atrac3_config_t));
		memset(at3_config, 0, sizeof(struct atrac3_config_t));
		at3_config->unk0 = 1;
		at3_config->unk1 = 1024;
		at3_config->unk2 = 1;
		at3_config->unk3 = 1;
		at3_config->unk4 = 1;
		at3_config->unk5 = 0;
		context->extradata = (Uint8 *)at3_config;
		context->extradata_size = 14;
		context->block_align = 192 * channels;
		context->bit_rate = bit_rate;
	}

	if (avcodec_open(context, codec->codec) < 0) {
		if (codec->codec->id == CODEC_ID_ATRAC3)
			av_free(context->extradata);
		av_free(context);
		SDL_UnlockMutex(orpGlobalMutex);
		orpPrintf("%s: codec context initialization failed.\n",
			codec->name.c_str());
		return -1;
	}
	SDL_UnlockMutex(orpGlobalMutex);

	return 0;
}

void orpStreamAudio::CloseDevice(void)
{
	SDL_CloseAudio();
}

void orpStreamAudio::CloseDecoder(void)
{
	if (!context) return;
	SDL_LockMutex(orpGlobalMutex);
	if (codec->codec->id == CODEC_ID_ATRAC3)
		av_free(context->extradata);
	avcodec_close(context);
	SDL_UnlockMutex(orpGlobalMutex);
	context = NULL;
}

Sint32 orpStreamAudio::Connect(string host, Uint16 port, string url, string session_id)
{
	orpStreamBase::Connect(host, port, url, session_id);
	if (InitDevice() != 0 || InitDecoder() != 0) return -1;
	thread_connection = SDL_CreateThread(orpThreadAudioConnection,
		(void *)this);
	if (!thread_connection) return -1;
	return 0;
}

orpStreamVideo::orpStreamVideo(struct orpCodec_t *codec)
	: orpStreamBase(ST_VIDEO, codec), terminate(false),
	frame_delay(0), thread_decode(NULL)
{
}

orpStreamVideo::~orpStreamVideo()
{
	terminate = true;
	buffer->Broadcast();

	Sint32 thread_result;
	if (thread_decode) SDL_WaitThread(thread_decode, &thread_result);

	CloseDecoder();
}

Sint32 orpStreamVideo::InitDecoder(void)
{
	SDL_LockMutex(orpGlobalMutex);
	context = avcodec_alloc_context();
	if (avcodec_open(context, codec->codec) < 0) {
		SDL_UnlockMutex(orpGlobalMutex);
		return -1;
	}
	SDL_UnlockMutex(orpGlobalMutex);

	sws_normal = sws_getContext(ORP_FRAME_WIDTH, ORP_FRAME_HEIGHT,
		context->pix_fmt, ORP_FRAME_WIDTH, ORP_FRAME_HEIGHT,
		PIX_FMT_YUV420P, SWS_BICUBIC, NULL, NULL, NULL);
	sws_medium = sws_getContext(ORP_FRAME_WIDTH, ORP_FRAME_HEIGHT,
		context->pix_fmt,
			(int)(ORP_FRAME_WIDTH * 1.5), (int)(ORP_FRAME_HEIGHT * 1.5),
		PIX_FMT_YUV420P, SWS_BICUBIC, NULL, NULL, NULL);
	sws_large = sws_getContext(ORP_FRAME_WIDTH, ORP_FRAME_HEIGHT,
		context->pix_fmt, ORP_FRAME_WIDTH * 2, ORP_FRAME_HEIGHT * 2,
		PIX_FMT_YUV420P, SWS_BICUBIC, NULL, NULL, NULL);
	sws_fullscreen = sws_getContext(ORP_FRAME_WIDTH, ORP_FRAME_HEIGHT,
		context->pix_fmt, view->fs.w, view->fs.h,
		PIX_FMT_YUV420P, SWS_BICUBIC, NULL, NULL, NULL);

	return 0;
}

void orpStreamVideo::ScaleFrame(AVFrame *f)
{
	AVPicture p;
	p.data[0] = view->overlay->pixels[0];
	p.data[1] = view->overlay->pixels[2];
	p.data[2] = view->overlay->pixels[1];

	p.linesize[0] = view->overlay->pitches[0];
	p.linesize[1] = view->overlay->pitches[2];
	p.linesize[2] = view->overlay->pitches[1];

	if (view->size == VIEW_NORMAL) {
		sws_scale(sws_normal,
			f->data, f->linesize, 0, context->height,
			p.data, p.linesize);
	} else if (view->size == VIEW_MEDIUM) {
		sws_scale(sws_medium,
			f->data, f->linesize, 0, context->height,
			p.data, p.linesize);
	} else if (view->size == VIEW_LARGE) {
		sws_scale(sws_large,
			f->data, f->linesize, 0, context->height,
			p.data, p.linesize);
	} else if (view->size == VIEW_FULLSCREEN) {
		sws_scale(sws_fullscreen,
			f->data, f->linesize, 0, context->height,
			p.data, p.linesize);
	}
}

void orpStreamVideo::CloseDecoder(void)
{
	if (context) {
		SDL_LockMutex(orpGlobalMutex);
		avcodec_close(context);
		SDL_UnlockMutex(orpGlobalMutex);
		context = NULL;
	}

	if (sws_normal) sws_freeContext(sws_normal);
	if (sws_medium) sws_freeContext(sws_medium);
	if (sws_large) sws_freeContext(sws_large);
	if (sws_fullscreen) sws_freeContext(sws_fullscreen);
	sws_normal = sws_medium = sws_large = sws_fullscreen = NULL;
}

Sint32 orpStreamVideo::Connect(string host, Uint16 port, string url, string session_id)
{
	orpStreamBase::Connect(host, port, url, session_id);
	if (InitDecoder() != 0) return -1;
	thread_connection = SDL_CreateThread(orpThreadVideoConnection,
		(void *)this);
	if (!thread_connection) return -1;
	thread_decode = SDL_CreateThread(orpThreadVideoDecode,
		(void *)this);
	if (!thread_decode) return -1;
	return 0;
}

OpenRemotePlay::OpenRemotePlay(struct orpConfig_t *config)
	: terminate(false), ps3_nickname(NULL), js(NULL),
	splash(NULL), font_normal(NULL), font_small(NULL),
	stream_audio(NULL), stream_video(NULL)
{
#if SDL_BYTEORDER == SDL_BIG_ENDIAN
	rmask = 0xff000000;
	gmask = 0x00ff0000;
	bmask = 0x0000ff00;
	amask = 0x000000ff;
#else
	rmask = 0x000000ff;
	gmask = 0x0000ff00;
	bmask = 0x00ff0000;
	amask = 0xff000000;
#endif
	memset(&view, 0, sizeof(struct orpView_t));
	view.scale.w = ORP_FRAME_WIDTH;
	view.scale.h = ORP_FRAME_HEIGHT;
	view.lock = SDL_CreateMutex();

	orpGlobalMutex = SDL_CreateMutex();

	// Copy config
	memcpy(&this->config, config, sizeof(struct orpConfig_t));

	// Init libcurl
	curl_global_init(CURL_GLOBAL_WIN32);

	// Init libavcodec, load all codecs
	avcodec_init();
	avcodec_register_all();
	av_log_set_callback(orpAVDebug);

	// Initialize the audio/video decoders we need
	struct orpCodec_t *oc;
	AVCodec *codec;

	codec = avcodec_find_decoder(CODEC_ID_H264);
	if (!codec) {
		orpPrintf("Required codec not found: %s\n", "CODEC_ID_H264");
		throw -1;
	}
	oc = new struct orpCodec_t;
	oc->name = "AVC";
	oc->codec = codec;
	this->codec.push_back(oc);

	codec = avcodec_find_decoder(CODEC_ID_MPEG4);
	if (!codec) {
		orpPrintf("Required codec not found: %s\n", "CODEC_ID_MPEG4");
		throw -1;
	}
	oc = new struct orpCodec_t;
	oc->name = "M4V";
	oc->codec = codec;
	this->codec.push_back(oc);

	codec = avcodec_find_decoder_by_name("libfaad");
	if (!codec) {
		orpPrintf("Required codec not found: %s\n", "CODEC_ID_AAC (libfaad)");
		throw -1;
	}
	oc = new struct orpCodec_t;
	oc->name = "M4A";
	oc->codec = codec;
	this->codec.push_back(oc);

	codec = avcodec_find_decoder(CODEC_ID_ATRAC3);
	if (!codec) {
		orpPrintf("Required codec not found: %s\n", "CODEC_ID_ATRAC3");
		throw -1;
	}
	oc = new struct orpCodec_t;
	oc->name = "AT3";
	oc->codec = codec;
	this->codec.push_back(oc);
}

OpenRemotePlay::~OpenRemotePlay()
{
	SessionDestroy();
	Sint32 i;
	for (i = 0; i < codec.size(); i++) delete codec[i];
	if (orpGlobalMutex) SDL_DestroyMutex(orpGlobalMutex);
	if (view.lock) SDL_DestroyMutex(view.lock);
	if (TTF_WasInit()) TTF_Quit();
	if (splash) SDL_FreeSurface(splash);
}

bool OpenRemotePlay::SessionCreate(void)
{
	Sint32 i;

	// Initialize audio, video, and timer
	if (SDL_Init(SDL_INIT_AUDIO | SDL_INIT_VIDEO | SDL_INIT_TIMER)) {
		orpPrintf("SDL_Init: %s\n", SDL_GetError());
		return false;
	}

	// Set window icon, must be done before setting video mode
	SDL_RWops *rw;
#ifndef _WIN32
	if ((rw = SDL_RWFromConstMem(icon_bmp, icon_bmp_len))) {
#else
	if ((rw = SDL_RWFromConstMem(icon_w32_bmp, icon_w32_bmp_len))) {
#endif
		SDL_Surface *icon = IMG_Load_RW(rw, 0);
		if (icon) {
			SDL_WM_SetIcon(icon, NULL);
			SDL_FreeSurface(icon);
		}
		SDL_FreeRW(rw);
	}

	// Determine desktop video resolution
	const SDL_VideoInfo *info = SDL_GetVideoInfo();
	if (info) {
		view.fs.x = 0;
		view.fs.w = info->current_w;
		view.fs.h = (Sint16)(info->current_w * ORP_FRAME_HEIGHT /
			ORP_FRAME_WIDTH);
		if (view.fs.h < info->current_h)
			view.fs.y = (info->current_h - view.fs.h) / 2;
		else view.fs.y = 0;
		view.desktop.w = info->current_w;
		view.desktop.h = info->current_h;
	} else {
		view.desktop.w = ORP_FRAME_WIDTH;
		view.desktop.h = ORP_FRAME_HEIGHT;
	}

	// Create window (set video mode)
	if (!view.view) { if (!CreateView()) return false; }

	// Initialize event thread
	SDL_InitSubSystem(SDL_INIT_EVENTTHREAD);

	// Initialize SDL TTF library
	if (TTF_Init() == -1) {
		orpPrintf("Error initializing SDL TTF: %s\n",
			TTF_GetError());
		return false;
	}

	if (!(rw = SDL_RWFromConstMem(font_ttf, font_ttf_len))) {
		orpPrintf("Error loading font.\n");
		return false;
	} else {
		font_small = TTF_OpenFontRW(rw, 1, 12);
		if (!font_small) {
			orpPrintf("Error opening font: %s\n",
				TTF_GetError());
			return false;
		}
		SDL_RWseek(rw, 0, SEEK_SET);
		font_normal = TTF_OpenFontRW(rw, 1, 18);
		if (!font_normal) {
			orpPrintf("Error opening font: %s\n",
				TTF_GetError());
			return false;
		}
	}

	// Set caption and display splash logo
	SetCaption(NULL);

	if ((rw = SDL_RWFromConstMem(splash_version_png, splash_version_png_len))) {
		splash = IMG_Load_RW(rw, 0);
		if (splash) {
			SDL_Rect rect;
			rect.x = rect.y = 0;
			rect.w = view.scale.w;
			rect.h = view.scale.h;
			SDL_BlitSurface(splash, NULL, view.view, &rect);

			SDL_Surface *surface;
			surface = SDL_CreateRGBSurface(SDL_SWSURFACE,
				ORP_FRAME_WIDTH, ORP_FRAME_HEIGHT, 32,
				rmask, gmask, bmask, amask);

			Sint32 i;
			for (i = 256; i > 0; i -= 16) {
				SDL_BlitSurface(splash, NULL, view.view, &rect);
				SDL_FillRect(surface, &rect, SDL_MapRGBA(surface->format, 0, 0, 0, (Uint8)i - 1));
				SDL_BlitSurface(surface, NULL, view.view, &rect);
				SDL_UpdateRect(view.view, rect.x, rect.y, rect.w, rect.h);
			}
			SDL_FreeSurface(surface);
		}
		SDL_FreeRW(rw);
	}

	if ((rw = SDL_RWFromConstMem(mode_game_png, mode_game_png_len))) {
		mode_game = IMG_Load_RW(rw, 0);
		SDL_FreeRW(rw);
	}
	if ((rw = SDL_RWFromConstMem(mode_ps1_png, mode_ps1_png_len))) {
		mode_ps1 = IMG_Load_RW(rw, 0);
		SDL_FreeRW(rw);
	}
	if ((rw = SDL_RWFromConstMem(mode_vsh_png, mode_vsh_png_len))) {
		mode_vsh = IMG_Load_RW(rw, 0);
		SDL_FreeRW(rw);
	}

	// Initialize joystick(s)
	if (SDL_InitSubSystem(SDL_INIT_JOYSTICK) == 0 &&
		SDL_NumJoysticks() > 0) {
		if ((!strncasecmp("sony", SDL_JoystickName(0), 4) ||
			!strncasecmp("playstation", SDL_JoystickName(0), 11) ||
			!strncasecmp("www.", SDL_JoystickName(0), 4)) &&
			(js = SDL_JoystickOpen(0))) {
			orpPrintf("Joystick opened: %s\n", SDL_JoystickName(0));
		}
	}

	// Allocate WoL packet
	UDPpacket *pkt_wol = SDLNet_AllocPacket(ORP_WOLPKT_LEN);
	pkt_wol->len = ORP_WOLPKT_LEN;
	memset(pkt_wol->data, 0, ORP_WOLPKT_LEN);
	for (i = 0; i < ORP_MAC_LEN; i++) pkt_wol->data[i] = 0xff;
	for (i = 0; i < 16; i++) {
		memcpy(pkt_wol->data + ORP_MAC_LEN + (i * ORP_MAC_LEN),
			config.ps3_mac, ORP_MAC_LEN);
	}

	UDPsocket skt;
	IPaddress addr;
	Sint32 channel;

	// Create and bind UDP socket for WoL reflector
	if (config.ps3_wolr) {
		skt = SDLNet_UDP_Open(0);
		if (SDLNet_ResolveHost(&addr,
			"wol.ps3-hacks.com", config.ps3_port) == 0 &&
			(channel = SDLNet_UDP_Bind(skt, -1, &addr)) != -1) {

			// Send WoL packet to reflector
			if (SDLNet_UDP_Send(skt, channel, pkt_wol) == 0) {
				orpPrintf("Error sending reflector WoL packet: %s\n",
					SDLNet_GetError());
			}
		}
		SDLNet_UDP_Close(skt);
	}

	// Create and bind UDP socket
	if (SDLNet_ResolveHost(&addr,
		config.ps3_addr, config.ps3_port) != 0) {
		orpPrintf("Error resolving address: %s:%d: %s\n",
			config.ps3_addr, config.ps3_port, SDLNet_GetError());
		DisplayError("Error resolving address!");
		return false;
	}
	skt = SDLNet_UDP_Open(0);
	if ((channel = SDLNet_UDP_Bind(skt, -1, &addr)) == -1) {
		orpPrintf("Error binding socket: %s\n", SDLNet_GetError());
		DisplayError("Error binding socket!");
		return false;
	}

	if (SDLNet_UDP_Send(skt, channel, pkt_wol) == 0) {
		orpPrintf("Error sending WoL packet: %s\n", SDLNet_GetError());
	}

	SDLNet_FreePacket(pkt_wol);

	// Direct TCP connection?
	if (!config.ps3_search) {
		SDLNet_UDP_Close(skt);
		return SessionPerform();
	}

	// UDP search for and/or wait on the PS3...
	struct PktAnnounceSrch_t srch;
	CreatePktAnnounceSrch(srch);
	UDPpacket *pkt_srch = SDLNet_AllocPacket(sizeof(struct PktAnnounceSrch_t));
	pkt_srch->len = sizeof(struct PktAnnounceSrch_t);
	memcpy(pkt_srch->data, &srch, sizeof(struct PktAnnounceSrch_t));
	UDPpacket *pkt_resp = SDLNet_AllocPacket(sizeof(struct PktAnnounceResp_t));

	ostringstream os;
	Sint32 reply = 0, first = 1;
	for (i = 0; i < ORP_SRCH_TIMEOUT; i++) {
		os.str("");
		os << "Searching... ";
		os << (i + 1) << "/" << ORP_SRCH_TIMEOUT;
		if (SetCaption(os.str().c_str())) break;

		if (SDLNet_UDP_Send(skt, channel, pkt_srch) == 0) {
			orpPrintf("Error sending packet: %s\n", SDLNet_GetError());
			DisplayError("Error sending packet!");
			break;
		}

		Sint32 result;
		if ((result = SDLNet_UDP_Recv(skt, pkt_resp)) == -1) {
			orpPrintf("Error receiving packet: %s\n", SDLNet_GetError());
			DisplayError("Error receiving packet!");
			break;
		}

		if (result == 0) {
			orpPrintf("No reply, retry %d of %d...\n",
				i + 1, ORP_SRCH_TIMEOUT);
			reply = 0;
			SDL_Delay(1000);
			continue;
		}

		reply++;
		orpPrintf("Reply of %d bytes.\n", pkt_resp->len);

		if (!first && reply < ORP_SRCH_REPLIES) {
			SDL_Delay(1000);
			continue;
		}

		// Fire it up!
		result = SessionPerform();
		if (result != EVENT_RESTORE) {
			if (!terminate) DisplayError("Connection terminated!");
			break;
		} else {
			orpPrintf("Waiting 5s for exec-mode switch.\n");
			SDL_Delay(5000);
		}
		i = reply = first = 0;
	}

	if (i >= ORP_SRCH_TIMEOUT)
		DisplayError("PlayStation""\x00AE""3 not found!");
	SDLNet_FreePacket(pkt_srch);
	SDLNet_FreePacket(pkt_resp);
	SDLNet_UDP_Close(skt);

	return true;
}

void OpenRemotePlay::SessionDestroy(void)
{
	if (view.view && view.size == VIEW_FULLSCREEN)
		SDL_SetVideoMode(view.scale.w, view.scale.h, 0, 0);
	view.view = NULL;
	if (view.overlay) SDL_FreeYUVOverlay(view.overlay);
	view.overlay = NULL;
	// TODO: This *always* crashes, not sure why...
	//if (js && SDL_JoystickOpened(0)) SDL_JoystickClose(js);
	SDL_Quit();
}

bool OpenRemotePlay::CreateView(void)
{
	SDL_Rect *r = NULL, fs;
	Uint32 flags = 0;
	switch (view.size)
	{
	case VIEW_FULLSCREEN:
		flags |= SDL_FULLSCREEN;
		fs.x = fs.y = 0;
		fs.w = view.desktop.w;
		fs.h = view.desktop.h;
		r = &fs;
		break;
	case VIEW_NORMAL:
		view.scale.w = ORP_FRAME_WIDTH;
		view.scale.h = ORP_FRAME_HEIGHT;
		break;
	case VIEW_MEDIUM:
		view.scale.w = (int)(ORP_FRAME_WIDTH * 1.5);
		view.scale.h = (int)(ORP_FRAME_HEIGHT * 1.5);
		break;
	case VIEW_LARGE:
		view.scale.w = ORP_FRAME_WIDTH * 2;
		view.scale.h = ORP_FRAME_HEIGHT * 2;
		break;
	}
	if (r == NULL) r = &view.scale;
	if (view.overlay) SDL_FreeYUVOverlay(view.overlay);
	if (!(view.view = SDL_SetVideoMode(r->w, r->h, 0, flags))) {
		orpPrintf("SDL_SetVideoMode: %s\n", SDL_GetError());
		return false;
	}
	if (view.size == VIEW_FULLSCREEN) r->h = view.fs.h;
	if (!(view.overlay = SDL_CreateYUVOverlay(
		r->w, r->h, SDL_YV12_OVERLAY, view.view))) {
		orpPrintf("SDL_CreateYUVOverlay: %s\n", SDL_GetError());
		return false;
	}
	if (view.status_bg) SDL_FreeSurface(view.status_bg);
	if (view.status_yuv) SDL_FreeYUVSurface(view.status_yuv);
	view.status_bg = SDL_CreateRGBSurface(SDL_SWSURFACE,
		r->w, ORP_OVERLAY_HEIGHT, 32, rmask, gmask, bmask, amask);
	view.status_yuv = SDL_CreateYUVSurface(r->w, ORP_OVERLAY_HEIGHT);
	UpdateOverlay();
	SDL_ShowCursor(!(view.size == VIEW_FULLSCREEN));
	SDL_WM_GrabInput((view.size == VIEW_FULLSCREEN)
		? SDL_GRAB_ON : SDL_GRAB_OFF);
	return true;
}

bool OpenRemotePlay::CreateKeys(const string &nonce, enum orpAuthType type)
{
	if (!orpDecodeKey(config.key.nonce, nonce)) {
		orpPrintf("Error decoding nonce: %s\n", nonce.c_str());
		return false;
	}

	memcpy(config.key.xor_pkey, config.key.pkey, ORP_KEY_LEN);
	memcpy(config.key.xor_nonce, config.key.nonce, ORP_KEY_LEN);

	Sint32 i;
	for (i = 0; i < ORP_KEY_LEN; i++)
		config.key.xor_pkey[i] ^= config.key.skey0[i];
	for (i = 0; i < ORP_KEY_LEN; i++)
		config.key.xor_nonce[i] ^= config.key.skey2[i];

	Uint8 auth_xor[4], auth_key[4];

	switch (type) {
	case orpAUTH_CHANGE_BITRATE:
		auth_key[0] = 'c';
		auth_key[1] = 'h';
		auth_key[2] = 'a';
		auth_key[3] = 'n' + 17;
		memcpy(auth_xor, config.key.xor_pkey, 4);
		for (i = 0; i < 4; i++) auth_xor[i] ^= auth_key[i];
		memcpy(config.key.xor_pkey, auth_xor, 4);
		break;

	case orpAUTH_SESSION_TERM:
		auth_key[0] = 's';
		auth_key[1] = 'e';
		auth_key[2] = 's';
		auth_key[3] = 's' + 17;
		memcpy(auth_xor, config.key.xor_pkey, 4);
		for (i = 0; i < 4; i++) auth_xor[i] ^= auth_key[i];
		memcpy(config.key.xor_pkey, auth_xor, 4);
		break;
	}

	memcpy(config.key.iv1, config.key.xor_nonce, ORP_KEY_LEN);

	Uint8 akey[ORP_KEY_LEN];
	memset(akey, 0, ORP_KEY_LEN);
	memcpy(akey, config.psp_mac, ORP_MAC_LEN);

	AES_KEY aes_key_encrypt;
	AES_set_encrypt_key(config.key.xor_pkey,
		ORP_KEY_LEN * 8, &aes_key_encrypt);
	AES_cbc_encrypt(akey, akey, ORP_KEY_LEN,
		&aes_key_encrypt, config.key.iv1, AES_ENCRYPT);

	Base64 base64;
	Uint8 *auth_encoded = NULL;
	auth_encoded = base64.Encode(akey, ORP_KEY_LEN);
	if (!auth_encoded) return false;

	switch (type) {
	case orpAUTH_CHANGE_BITRATE:
		if (config.key.auth_change_bitrate)
			delete [] config.key.auth_change_bitrate;
		config.key.auth_change_bitrate = auth_encoded;
		break;
	case orpAUTH_SESSION_TERM:
		if (config.key.auth_session_term)
			delete [] config.key.auth_session_term;
		config.key.auth_session_term = auth_encoded;
		break;
	default:
	case orpAUTH_NORMAL:
		if (config.key.auth_normal) delete [] config.key.auth_normal;
		config.key.auth_normal = auth_encoded;
		break;
	}

	return true;
}

bool OpenRemotePlay::SetCaption(const char *caption)
{
	os_caption.str("");
	if (ps3_nickname) {
		os_caption << ps3_nickname << " - ";
		if (!caption) {
			switch (config.bitrate) {
			case CTRL_BR_256:
				os_caption << "256k";
				break;
			case CTRL_BR_384:
				os_caption << "384k";
				break;
			case CTRL_BR_512:
				os_caption << "512k";
				break;
			case CTRL_BR_768:
				os_caption << "768k";
				break;
			case CTRL_BR_1024:
				os_caption << "1024k";
				break;
			}
		}
	}
	else if (!caption) os_caption << "Open Remote Play";

	if (caption) os_caption << caption;
	SDL_WM_SetCaption(os_caption.str().c_str(), NULL);
	UpdateOverlay();
	SDL_Event event;
	bool quit = false;
	while (SDL_PollEvent(&event) > 0) {
		if (event.type == SDL_QUIT || (event.type == SDL_KEYDOWN &&
			event.key.keysym.sym == SDLK_q &&
			event.key.keysym.mod & (KMOD_LCTRL | KMOD_RCTRL))) {
			quit = true;
		}
	}
	return quit;
}

struct orpCodec_t *OpenRemotePlay::GetCodec(const string &name)
{
	Uint32 i;
	for (i = 0; i < codec.size(); i++) {
		if (strcasecmp(name.c_str(), codec[i]->name.c_str())) continue;
		return codec[i];
	}
	return NULL;
}

Sint32 OpenRemotePlay::ControlPerform(CURL *curl, struct orpCtrlMode_t *mode)
{
	struct curl_slist *headers = NULL;

	ostringstream os;
	os << "Host:";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Accept: */*;q=0.01";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Accept-Encoding:\"\"";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Accept-Charset: iso-8859-1;q=0.01";
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Host: " << config.ps3_addr << ":" << config.ps3_port;
	headers = curl_slist_append(headers, os.str().c_str());

	if (mode->mode == CTRL_CHANGE_BITRATE) {
		os.str("");
		os << orpGetHeader(HEADER_CTRL_MODE);
		os << ": " << "change-bitrate";
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << orpGetHeader(HEADER_CTRL_BITRATE);
		os << ": " << mode->param1;
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << orpGetHeader(HEADER_CTRL_MAXBITRATE);
		os << ": " << mode->param2;
		headers = curl_slist_append(headers, os.str().c_str());
	} else if (mode->mode == CTRL_SESSION_TERM) {
		os.str("");
		os << orpGetHeader(HEADER_CTRL_MODE);
		os << ": " << "session-term";
		headers = curl_slist_append(headers, os.str().c_str());
	}

	if (config.net_public) {
		os.str("");
		os << orpGetHeader(HEADER_AUTH);
		if (mode->mode == CTRL_CHANGE_BITRATE)
			os << ": " << (const char *)config.key.auth_change_bitrate;
		else if (mode->mode == CTRL_SESSION_TERM)
			os << ": " << (const char *)config.key.auth_session_term;
		headers = curl_slist_append(headers, os.str().c_str());
	}

	os.str("");
	os << orpGetHeader(HEADER_SESSIONID);
	os << ": " << session_id;
	headers = curl_slist_append(headers, os.str().c_str());

	os.str("");
	os << "Connection: Keep-Alive";
	headers = curl_slist_append(headers, os.str().c_str());

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	CURLcode cc;
	cc = curl_easy_perform(curl);
	curl_slist_free_all(headers);
	headers = NULL;

	if (cc != 0) return -1;

	Uint32 code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

	return (Sint32)code;
}

#if 0
static void orpDumpPadState(Uint8 *state)
{
	bool toggle = false;
	Uint32 x, y, i = 0;
	for (y = 0; y < 4; y++) {
		for (x = 0; x < 32; x++) {
			orpPrintf("%02x", state[i]);
			if (toggle) {
				orpPrintf(" ");
				toggle = false;
			} else toggle = true;
			i++;
		}
		orpPrintf("\n");
	}
}
#endif

Sint32 OpenRemotePlay::SendPadState(Uint8 *pad, Uint32 id, Uint32 &count, Uint32 timestamp, vector<string> &headers)
{
	if (id != 0) {
		Uint32 be_id = SDL_Swap32(id);
		Uint32 be_timestamp = SDL_Swap32(timestamp);
		memcpy(pad + ORP_PAD_EVENTID, &be_id, 4);
		memcpy(pad + ORP_PAD_TIMESTAMP, &be_timestamp, 4);
	}
	//orpDumpPadState(statePad);

	if (config.net_public) {
		Uint8 pad_crypt[ORP_PADSTATE_LEN];
		memset(pad_crypt, 0, ORP_PADSTATE_LEN);
		static AES_KEY *aes_key = NULL;
		if (!aes_key) {
			aes_key = new AES_KEY;
			AES_set_encrypt_key(config.key.xor_pkey,
				ORP_KEY_LEN * 8, aes_key);
			memcpy(config.key.iv1,
				config.key.xor_nonce, ORP_KEY_LEN);
		}
		AES_cbc_encrypt(pad, pad_crypt,
			ORP_PADSTATE_LEN,
			aes_key, config.key.iv1, AES_ENCRYPT);

		SDLNet_TCP_Send(skt_pad, pad_crypt, ORP_PADSTATE_LEN);
	}
	else
		SDLNet_TCP_Send(skt_pad, pad, ORP_PADSTATE_LEN);

	if (count == ORP_PADSTATE_MAX) {
		// TODO: Yes this is lazy, and not right...
		Uint8 reply[80];
		if (SDLNet_TCP_Recv(skt_pad, reply, 80) != 80) {
			orpPrintf("Error receiving reply: %s\n", SDLNet_GetError());
			return -1;
		}
		count = 0;
		Uint32 i;
		for (i = 0; i < headers.size(); i++) {
			SDLNet_TCP_Send(skt_pad,
				headers[i].c_str(), strlen(headers[i].c_str()));
		}
	}

	return 0;
}

static struct orpKeyboardMap_t orpKeyboardMap[ORP_KBMAP_LEN] = {
	// 1 2 3 4 5 6 7 8 9 0
	{ SDLK_1, KMOD_NONE, 0, 0 },
	{ SDLK_2, KMOD_NONE, 1, 0 },
	{ SDLK_3, KMOD_NONE, 2, 0 },
	{ SDLK_4, KMOD_NONE, 3, 0 },
	{ SDLK_5, KMOD_NONE, 4, 0 },
	{ SDLK_6, KMOD_NONE, 5, 0 },
	{ SDLK_7, KMOD_NONE, 6, 0 },
	{ SDLK_8, KMOD_NONE, 7, 0 },
	{ SDLK_9, KMOD_NONE, 8, 0 },
	{ SDLK_0, KMOD_NONE, 9, 0 },
	// q w e r t y u i o p
	{ SDLK_q, KMOD_NONE, 0, 1 },
	{ SDLK_w, KMOD_NONE, 1, 1 },
	{ SDLK_e, KMOD_NONE, 2, 1 },
	{ SDLK_r, KMOD_NONE, 3, 1 },
	{ SDLK_t, KMOD_NONE, 4, 1 },
	{ SDLK_y, KMOD_NONE, 5, 1 },
	{ SDLK_u, KMOD_NONE, 6, 1 },
	{ SDLK_i, KMOD_NONE, 7, 1 },
	{ SDLK_o, KMOD_NONE, 8, 1 },
	{ SDLK_p, KMOD_NONE, 9, 1 },
	// a s d f g h j k l '
	{ SDLK_a, KMOD_NONE, 0, 2 },
	{ SDLK_s, KMOD_NONE, 1, 2 },
	{ SDLK_d, KMOD_NONE, 2, 2 },
	{ SDLK_f, KMOD_NONE, 3, 2 },
	{ SDLK_g, KMOD_NONE, 4, 2 },
	{ SDLK_h, KMOD_NONE, 5, 2 },
	{ SDLK_j, KMOD_NONE, 6, 2 },
	{ SDLK_k, KMOD_NONE, 7, 2 },
	{ SDLK_l, KMOD_NONE, 8, 2 },
	{ SDLK_QUOTE, KMOD_NONE, 9, 2 },
	// z x c v b n m , . ?
	{ SDLK_z, KMOD_NONE, 0, 3 },
	{ SDLK_x, KMOD_NONE, 1, 3 },
	{ SDLK_c, KMOD_NONE, 2, 3 },
	{ SDLK_v, KMOD_NONE, 3, 3 },
	{ SDLK_b, KMOD_NONE, 4, 3 },
	{ SDLK_n, KMOD_NONE, 5, 3 },
	{ SDLK_m, KMOD_NONE, 6, 3 },
	{ SDLK_COMMA, KMOD_NONE, 7, 3 },
	{ SDLK_PERIOD, KMOD_NONE, 8, 3 },
	{ SDLK_SLASH, KMOD_SHIFT , 9, 3 },
	// symbols, shift, extra-char, etc...
	{ SDLK_UNKNOWN, KMOD_NONE, 0, 4 },
	{ SDLK_UNKNOWN, KMOD_NONE, 1, 4 },
	{ SDLK_UNKNOWN, KMOD_NONE, 2, 4 },
	{ SDLK_UNKNOWN, KMOD_NONE, 3, 4 },
	{ SDLK_UNKNOWN, KMOD_NONE, 4, 4 },
	{ SDLK_UNKNOWN, KMOD_NONE, 4, 4 },
	{ SDLK_UNKNOWN, KMOD_NONE, 6, 4 },
	{ SDLK_UNKNOWN, KMOD_NONE, 6, 4 },
	{ SDLK_RETURN, KMOD_NONE, 9, 4 },
	{ SDLK_UNKNOWN, KMOD_NONE, 9, 4 },
	// arrow buttons, input mode, enter, etc...
/*	{ SDLK_UP, KMOD_NONE, 0, 5 },
	{ SDLK_DOWN, KMOD_NONE, 1, 5 }, */
	{ SDLK_UNKNOWN, KMOD_NONE, 0, 5 },
	{ SDLK_UNKNOWN, KMOD_NONE, 1, 5 },
	{ SDLK_UNKNOWN, KMOD_NONE, 2, 5 },
	{ SDLK_UNKNOWN, KMOD_NONE, 3, 5 },
	{ SDLK_UNKNOWN, KMOD_NONE, 4, 5 },
	{ SDLK_UNKNOWN, KMOD_NONE, 5, 5 },
	{ SDLK_UNKNOWN, KMOD_NONE, 6, 5 },
	{ SDLK_UNKNOWN, KMOD_NONE, 6, 5 },
	{ SDLK_UNKNOWN, KMOD_NONE, 8, 5 },
	{ SDLK_UNKNOWN, KMOD_NONE, 8, 5 },
};

Sint32 OpenRemotePlay::SessionControl(CURL *curl)
{
	IPaddress ip;
	if (SDLNet_ResolveHost(&ip, config.ps3_addr, config.ps3_port) != 0) {
		orpPrintf("Error resolving address: %s:%d: %s\n",
			config.ps3_addr, config.ps3_port, SDLNet_GetError());
		return -1;
	}

	if ((skt_pad = SDLNet_TCP_Open(&ip)) == NULL) {
		orpPrintf("Input connection failure: %s\n", SDLNet_GetError());
		return -1;
	}

	vector<string> headers;

	ostringstream os;
	os << "POST " << ORP_POST_PAD << " HTTP/1.1\r\n";
	headers.push_back(os.str());

	os.str("");
	os << "User-Agent: " <<  ORP_USER_AGENT << "\r\n";
	headers.push_back(os.str());

	os.str("");
	os << "Accept: */*;q=0.01\r\n";
	headers.push_back(os.str());

	os.str("");
	os << "Accept-Encoding: \r\n";
	headers.push_back(os.str());

	os.str("");
	os << "Accept-Charset: iso-8859-1;q=0.01\r\n";
	headers.push_back(os.str());

	os.str("");
	os << "Host: " << config.ps3_addr << ":" << config.ps3_port << "\r\n";
	headers.push_back(os.str());

	os.str("");
	os << orpGetHeader(HEADER_PAD_INDEX) << ": 1\r\n";
	headers.push_back(os.str());

	os.str("");
	os << orpGetHeader(HEADER_SESSIONID);
	os << ": " << session_id << "\r\n";
	headers.push_back(os.str());

	os.str("");
	os << "Connection: Keep-Alive\r\n";
	headers.push_back(os.str());

	os.str("");
	os << "Content-Length: " << (ORP_PADSTATE_MAX * ORP_PADSTATE_LEN);
	os << "\r\n";
	headers.push_back(os.str());

	headers.push_back("\r\n");

	Uint32 i = 0;
	for (i = 0; i < headers.size(); i++)
		SDLNet_TCP_Send(skt_pad, headers[i].c_str(), strlen(headers[i].c_str()));

	Uint8 statePad[ORP_PADSTATE_LEN] = {
		0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x80, 0x00, 0x80, 0x00, 0x80, 0x00, 0x80,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	Uint8 statePadHome[ORP_PADSTATE_LEN] = {
		0x00, 0x01, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x80, 0x00, 0x80, 0x00, 0x80, 0x00, 0x80,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	struct orpCtrlMode_t mode;

	bool kbmap_mode = false;
	Sint8 kbmap_cx = ORP_KBMAP_SX;
	Sint8 kbmap_cy = ORP_KBMAP_SY;
	vector<Uint32> kbmap_queue;

	Uint32 count = 0;
	Uint32 id = 0;
	Uint32 timestamp;
	Uint32 ticks = SDL_GetTicks();
	Sint16 jsr_xaxis = 0x80, jsr_yaxis = 0x80;
	Sint16 jsl_xaxis = 0x80, jsl_yaxis = 0x80;
	Sint16 mouse_x = 0, mouse_y = 0;
	Uint8 *keystate = SDL_GetKeyState(NULL);;
	SDL_Event event;

	// Flush any queued events...
	while (SDL_PollEvent(&event) > 0) orpPrintf("Flushing event...\n");

	// Main event loop
	for ( ;; ) {
		Uint32 key = 0;
		if (SDL_WaitEvent(&event) == 0) {
			orpPrintf("SDL_WaitEvent: %s\n", SDL_GetError());
			return -1;
		}
		switch (event.type) {
		case SDL_QUIT:
			terminate = true;
			mode.mode = CTRL_SESSION_TERM;
			ControlPerform(curl, &mode);
			return 0;

		case SDL_USEREVENT:
			switch (event.user.code) {
			case EVENT_ERROR:
				terminate = true;
				mode.mode = CTRL_SESSION_TERM;
				ControlPerform(curl, &mode);
				DisplayError((const char *)event.user.data1);
				free(event.user.data1);
				break;
			case EVENT_RESTORE:
				orpPrintf("Restore event\n");
				SDLNet_TCP_Close(skt_pad);
				if (curl) {
					mode.mode = CTRL_SESSION_TERM;
					ControlPerform(curl, &mode);
					curl_easy_cleanup(curl);
					curl = NULL;
				}
				return EVENT_RESTORE;
			case EVENT_SHUTDOWN:
				terminate = true;
				mode.mode = CTRL_SESSION_TERM;
				ControlPerform(curl, &mode);
				return 0;
			case EVENT_STREAM_EXIT:
				orpPrintf("Stream exited\n");
				SDLNet_TCP_Close(skt_pad);
				if (curl) {
					curl_easy_cleanup(curl);
					curl = NULL;
				}
				if (!terminate) return EVENT_RESTORE;
				return EVENT_STREAM_EXIT;
			}
			break;

		case SDL_KEYUP:
			switch (event.key.keysym.sym) {
			case SDLK_UP:
				if (!kbmap_mode)
					key = ORP_PAD_KEYUP | ORP_PAD_PSP_DPUP;
				break;
			case SDLK_RIGHT:
				if (kbmap_mode)
					key = ORP_PAD_KEYUP | ORP_PAD_PSP_R1;
				else
					key = ORP_PAD_KEYUP | ORP_PAD_PSP_DPRIGHT;
				break;
			case SDLK_DOWN:
				if (!kbmap_mode)
					key = ORP_PAD_KEYUP | ORP_PAD_PSP_DPDOWN;
				break;
			case SDLK_LEFT:
				if (kbmap_mode)
					key = ORP_PAD_KEYUP | ORP_PAD_PSP_L1;
				else
					key = ORP_PAD_KEYUP | ORP_PAD_PSP_DPLEFT;
				break;
			case SDLK_RETURN:
				if (!(event.key.keysym.mod & (KMOD_LCTRL | KMOD_RCTRL))) {
//					if (kbmap_mode)
//						key = ORP_PAD_KEYUP | ORP_PAD_PSP_START;
//					else
					if (!kbmap_mode)
						key = ORP_PAD_KEYUP | ORP_PAD_PSP_X;
				}
				break;
			case SDLK_F1:
			case SDLK_SPACE:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_TRI;
				break;
			case SDLK_F2:
			case SDLK_BACKSPACE:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_SQUARE;
				break;
			case SDLK_F3:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_SELECT;
				break;
			case SDLK_F4:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_START;
				break;
			case SDLK_PAGEUP:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_L1;
				break;
			case SDLK_PAGEDOWN:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_R1;
				break;
			case SDLK_ESCAPE:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_CIRCLE;
				break;
			}
			break;

		case SDL_KEYDOWN:
			if (kbmap_mode) {
				bool found = false;
				Sint8 tx = 0, ty = 0;
				for (i = 0; i < ORP_KBMAP_LEN; i++) {
					if (orpKeyboardMap[i].sym != event.key.keysym.sym)
						continue;
					if (event.key.keysym.mod &&
						!(orpKeyboardMap[i].mod & event.key.keysym.mod))
						continue;
					tx = orpKeyboardMap[i].x;
					ty = orpKeyboardMap[i].y;
					found = true;
					break;
				}
				if (found) {
					Sint8 dx = (tx + 1) - (kbmap_cx + 1);
					Sint8 dy = (ty + 1) - (kbmap_cy + 1);
					if (dy > 0) {
						for (i = 0; i < abs(dx); i++) {
							if (dx > 0)
								kbmap_queue.push_back(ORP_PAD_PSP_DPRIGHT);
							else if (dx < 0)
								kbmap_queue.push_back(ORP_PAD_PSP_DPLEFT);
						}
						for (i = 0; i < abs(dy); i++) {
							if (dy > 0)
								kbmap_queue.push_back(ORP_PAD_PSP_DPDOWN);
							else if (dy < 0)
								kbmap_queue.push_back(ORP_PAD_PSP_DPUP);
						}
					} else {
						for (i = 0; i < abs(dy); i++) {
							if (dy > 0)
								kbmap_queue.push_back(ORP_PAD_PSP_DPDOWN);
							else if (dy < 0)
								kbmap_queue.push_back(ORP_PAD_PSP_DPUP);
						}
						for (i = 0; i < abs(dx); i++) {
							if (dx > 0)
								kbmap_queue.push_back(ORP_PAD_PSP_DPRIGHT);
							else if (dx < 0)
								kbmap_queue.push_back(ORP_PAD_PSP_DPLEFT);
						}
					}
					kbmap_queue.push_back(ORP_PAD_PSP_X);
					kbmap_cx = dx + kbmap_cx;
					kbmap_cy = dy + kbmap_cy;
					break;
				}
				if (event.key.keysym.sym == SDLK_SPACE) {
					kbmap_queue.push_back(ORP_PAD_PSP_TRI);
					break;
				} else if (event.key.keysym.sym == SDLK_BACKSPACE) {
					kbmap_queue.push_back(ORP_PAD_PSP_SQUARE);
					break;
				}
			}
			switch (event.key.keysym.sym) {
			case SDLK_q:
				if (event.key.keysym.mod & (KMOD_LCTRL | KMOD_RCTRL)) {
					mode.mode = CTRL_SESSION_TERM;
					ControlPerform(curl, &mode);
					terminate = true;
					return 0;
				}
				break;
			case SDLK_1:
				if (event.key.keysym.mod & (KMOD_LCTRL |  KMOD_RCTRL)) {
					mode.mode = CTRL_CHANGE_BITRATE;
					mode.param1 = "1024000";
					mode.param2 = "1024000";
					config.bitrate = CTRL_BR_1024;
					ControlPerform(curl, &mode);
					SetCaption(NULL);
				}
				break;
			case SDLK_2:
				if (event.key.keysym.mod & (KMOD_LCTRL |  KMOD_RCTRL)) {
					mode.mode = CTRL_CHANGE_BITRATE;
					mode.param1 = "768000";
					mode.param2 = "1024000";
					config.bitrate = CTRL_BR_768;
					ControlPerform(curl, &mode);
					SetCaption(NULL);
				}
				break;
			case SDLK_3:
				if (event.key.keysym.mod & (KMOD_LCTRL |  KMOD_RCTRL)) {
					mode.mode = CTRL_CHANGE_BITRATE;
					mode.param1 = "384000";
					mode.param2 = "1024000";
					config.bitrate = CTRL_BR_384;
					ControlPerform(curl, &mode);
					SetCaption(NULL);
				}
				break;
			case SDLK_s:
				if ((event.key.keysym.mod & (KMOD_LCTRL |  KMOD_RCTRL))) {
					SDL_LockMutex(view.lock);
					view.status_sticky = view.status_sticky ? false : true;
					UpdateOverlay();
					view.status_ticks = 0;
					SDL_UnlockMutex(view.lock);
				}
				break;
			case SDLK_d:
				if ((event.key.keysym.mod & (KMOD_LCTRL |  KMOD_RCTRL)) &&
					view.size != VIEW_FULLSCREEN) {
					SDL_LockMutex(view.lock);
					if (view.size == VIEW_NORMAL)
						view.size = VIEW_MEDIUM;
					else if (view.size == VIEW_MEDIUM)
						view.size = VIEW_LARGE;
					else if (view.size == VIEW_LARGE)
						view.size = VIEW_NORMAL;
					CreateView();
					SDL_UnlockMutex(view.lock);
					while (SDL_PollEvent(&event) > 0);
				}
				break;
			case SDLK_f:
			case SDLK_F11:
				if ((event.key.keysym.mod & (KMOD_LCTRL | KMOD_RCTRL)) ||
					(event.key.keysym.sym == SDLK_F11 &&
						!(event.key.keysym.mod &
						(KMOD_CTRL | KMOD_SHIFT | KMOD_ALT)))) {
					SDL_LockMutex(view.lock);
					if (view.size == VIEW_FULLSCREEN)
						view.size = view.prev;
					else {
						view.prev = view.size;
						view.size = VIEW_FULLSCREEN;
					}
					CreateView();
					SDL_UnlockMutex(view.lock);
					while (SDL_PollEvent(&event) > 0);
				}
				break;
			case SDLK_UP:
				if (!kbmap_mode)
					key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_DPUP;
				break;
			case SDLK_RIGHT:
				if (kbmap_mode)
					key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_R1;
				else
					key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_DPRIGHT;
				break;
			case SDLK_DOWN:
				if (!kbmap_mode)
					key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_DPDOWN;
				break;
			case SDLK_LEFT:
				if (kbmap_mode)
					key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_L1;
				else
					key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_DPLEFT;
				break;
			case SDLK_RETURN:
				if (!(event.key.keysym.mod & (KMOD_LCTRL | KMOD_RCTRL))) {
//					if (kbmap_mode)
//						key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_START;
//					else
					if (!kbmap_mode)
						key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_X;
				} else {
					if (kbmap_mode == true) {
						SetCaption(NULL);
						kbmap_mode = false;
					} else {
						SetCaption("Virtual Keyboard Mode");
						kbmap_mode = true;
						kbmap_cx = ORP_KBMAP_SX;
						kbmap_cy = ORP_KBMAP_SY;
					}
				}
				break;
			case SDLK_ESCAPE:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_CIRCLE;
				break;
			case SDLK_F1:
			case SDLK_SPACE:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_TRI;
				break;
			case SDLK_F2:
			case SDLK_BACKSPACE:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_SQUARE;
				break;
			case SDLK_F3:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_SELECT;
				break;
			case SDLK_F4:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_START;
				break;
			case SDLK_PAGEUP:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_L1;
				break;
			case SDLK_PAGEDOWN:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_R1;
				break;
			case SDLK_HOME:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_HOME;
				break;
			}
			break;

		case SDL_MOUSEMOTION:
			if (SDL_WM_GrabInput(SDL_GRAB_QUERY) != SDL_GRAB_ON) break;
			if (!keystate[SDLK_RALT] && !keystate[SDLK_LALT]) break;
			mouse_x += event.motion.xrel;
			mouse_y += event.motion.yrel;
			if (mouse_x > SCHAR_MAX) mouse_x = SCHAR_MAX;
			else if (mouse_x < SCHAR_MIN) mouse_x = SCHAR_MIN;
			if (mouse_y > SCHAR_MAX) mouse_y = SCHAR_MAX;
			else if (mouse_y < SCHAR_MIN) mouse_y = SCHAR_MIN;
			if (event.motion.xrel) {
				key = ORP_PAD_PSP_LXAXIS;
				jsl_xaxis = mouse_x + 0x80;
			}
			else if (event.motion.yrel) {
				key = ORP_PAD_PSP_LYAXIS;
				jsl_yaxis = mouse_y + 0x80;
			}
#if 0
			if (abs(event.motion.xrel) < 3 && abs(event.motion.yrel) < 3) {
				key = ORP_PAD_KEYUP;
				key += (ORP_PAD_PSP_DPRIGHT | ORP_PAD_PSP_DPUP |
					ORP_PAD_PSP_DPLEFT | ORP_PAD_PSP_DPDOWN);
			} else if (abs(event.motion.xrel) > abs(event.motion.yrel)) {
				key = ORP_PAD_KEYDOWN;
				if (event.motion.xrel > 0)
					key += ORP_PAD_PSP_DPRIGHT;
				else
					key += ORP_PAD_PSP_DPLEFT;
			} else if (abs(event.motion.xrel) < abs(event.motion.yrel)) {
				key = ORP_PAD_KEYDOWN;
				if (event.motion.yrel > 0)
					key += ORP_PAD_PSP_DPDOWN;
				else
					key += ORP_PAD_PSP_DPUP;
			} else {
				key = ORP_PAD_KEYUP;
				key += (ORP_PAD_PSP_DPRIGHT | ORP_PAD_PSP_DPUP |
					ORP_PAD_PSP_DPLEFT | ORP_PAD_PSP_DPDOWN);
			}
#endif
			break;

		case SDL_JOYBUTTONUP:
			switch (event.jbutton.button) {
			case ORP_DS3_SELECT:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_SELECT;
				break;
			case ORP_DS3_L3:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_L3;
				break;
			case ORP_DS3_R3:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_R3;
				break;
			case ORP_DS3_START:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_START;
				break;
			case ORP_DS3_DPUP:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_DPUP;
				break;
			case ORP_DS3_DPRIGHT:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_DPRIGHT;
				break;
			case ORP_DS3_DPDOWN:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_DPDOWN;
				break;
			case ORP_DS3_DPLEFT:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_DPLEFT;
				break;
			case ORP_DS3_L2:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_L2;
				break;
			case ORP_DS3_R2:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_R2;
				break;
			case ORP_DS3_L1:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_L1;
				break;
			case ORP_DS3_R1:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_R1;
				break;
			case ORP_DS3_TRI:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_TRI;
				break;
			case ORP_DS3_CIRCLE:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_CIRCLE;
				break;
			case ORP_DS3_X:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_X;
				break;
			case ORP_DS3_SQUARE:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_SQUARE;
				break;
			}
			break;

		case SDL_JOYBUTTONDOWN:
			switch (event.jbutton.button) {
			case ORP_DS3_SELECT:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_SELECT;
				break;
			case ORP_DS3_L3:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_L3;
				break;
			case ORP_DS3_R3:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_R3;
				break;
			case ORP_DS3_START:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_START;
				break;
			case ORP_DS3_DPUP:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_DPUP;
				break;
			case ORP_DS3_DPRIGHT:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_DPRIGHT;
				break;
			case ORP_DS3_DPDOWN:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_DPDOWN;
				break;
			case ORP_DS3_DPLEFT:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_DPLEFT;
				break;
			case ORP_DS3_L2:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_L2;
				break;
			case ORP_DS3_R2:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_R2;
				break;
			case ORP_DS3_L1:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_L1;
				break;
			case ORP_DS3_R1:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_R1;
				break;
			case ORP_DS3_TRI:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_TRI;
				break;
			case ORP_DS3_CIRCLE:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_CIRCLE;
				break;
			case ORP_DS3_X:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_X;
				break;
			case ORP_DS3_SQUARE:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_SQUARE;
				break;
			case ORP_DS3_HOME:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_HOME;
				break;
			}
			break;

		case SDL_JOYAXISMOTION:
			switch (event.jaxis.axis) {
			case 0:
				key = ORP_PAD_PSP_LXAXIS;
				if (event.jaxis.value >= 0) {
					jsl_xaxis = (short)(event.jaxis.value *
						(short)SCHAR_MAX / (short)SHRT_MAX) + 0x80;
				} else {
					jsl_xaxis = (short)(event.jaxis.value *
						(short)SCHAR_MIN / (short)SHRT_MIN) + 0x80;
				}
				break;
			case 1:
				key = ORP_PAD_PSP_LYAXIS;
				if (event.jaxis.value >= 0) {
					jsl_yaxis = (short)(event.jaxis.value *
						(short)SCHAR_MAX / (short)SHRT_MAX) + 0x80;
				} else {
					jsl_yaxis = (short)(event.jaxis.value *
						(short)SCHAR_MIN / (short)SHRT_MIN) + 0x80;
				}
				break;
			case 2:
				key = ORP_PAD_PSP_RXAXIS;
				if (event.jaxis.value >= 0) {
					jsr_xaxis = (short)(event.jaxis.value *
						(short)SCHAR_MAX / (short)SHRT_MAX) + 0x80;
				} else {
					jsr_xaxis = (short)(event.jaxis.value *
						(short)SCHAR_MIN / (short)SHRT_MIN) + 0x80;
				}
				break;
			case 3:
				key = ORP_PAD_PSP_RYAXIS;
				if (event.jaxis.value >= 0) {
					jsr_yaxis = (short)(event.jaxis.value *
						(short)SCHAR_MAX / (short)SHRT_MAX) + 0x80;
				} else {
					jsr_yaxis = (short)(event.jaxis.value *
						(short)SCHAR_MIN / (short)SHRT_MIN) + 0x80;
				}
				break;
			}
			break;

		case SDL_MOUSEBUTTONUP:
			switch (event.button.button) {
			case SDL_BUTTON_LEFT:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_X;
				break;
			case SDL_BUTTON_RIGHT:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_TRI;
				break;
			case SDL_BUTTON_WHEELUP:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_DPUP;
				SDL_Delay(50);
				break;
			case SDL_BUTTON_WHEELDOWN:
				key = ORP_PAD_KEYUP | ORP_PAD_PSP_DPDOWN;
				SDL_Delay(50);
				break;
			}
			break;

		case SDL_MOUSEBUTTONDOWN:
			switch (event.button.button) {
			case SDL_BUTTON_LEFT:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_X;
				break;
			case SDL_BUTTON_MIDDLE:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_HOME;
				break;
			case SDL_BUTTON_RIGHT:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_TRI;
				break;
			case SDL_BUTTON_WHEELUP:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_DPUP;
				break;
			case SDL_BUTTON_WHEELDOWN:
				key = ORP_PAD_KEYDOWN | ORP_PAD_PSP_DPDOWN;
				break;
			}
			break;
		}

		if (key) {
			count++;
			Uint16 value = (Uint16)(key & 0x0000ffff);

			if (value == ORP_PAD_PSP_HOME) {
				//orpDumpPadState(statePadHome);
				//SDLNet_TCP_Send(skt_pad, statePadHome, ORP_PADSTATE_LEN);
				SendPadState(statePadHome, 0, count, 0, headers);
				continue;
			}

			if (key & ORP_PAD_KEYUP) {
				statePad[((value & 0xff00) >> 8)] &=
					~((Uint8)(value & 0x00ff));
			} else if (key & ORP_PAD_KEYDOWN) {
				statePad[((value & 0xff00) >> 8)] |=
					((Uint8)(value & 0x00ff));
			} else if (key == ORP_PAD_PSP_LXAXIS) {
				jsl_xaxis = SDL_Swap16(jsl_xaxis);
				memcpy(statePad + key, &jsl_xaxis, sizeof(Sint16));
			} else if (key == ORP_PAD_PSP_LYAXIS) {
				jsl_yaxis = SDL_Swap16(jsl_yaxis);
				memcpy(statePad + key, &jsl_yaxis, sizeof(Sint16));
			} else if (key == ORP_PAD_PSP_RXAXIS) {
				jsr_xaxis = SDL_Swap16(jsr_xaxis);
				memcpy(statePad + key, &jsr_xaxis, sizeof(Sint16));
			} else if (key == ORP_PAD_PSP_RYAXIS) {
				jsr_yaxis = SDL_Swap16(jsr_yaxis);
				memcpy(statePad + key, &jsr_yaxis, sizeof(Sint16));
			}

			id++;
			// TODO: This calculation is very approximate, needs to be fixed!
			timestamp = (SDL_GetTicks() - ticks) / 10;	

			SendPadState(statePad, id, count, timestamp, headers);
			//SendPadState(statePad, id, count, 0, headers);

		} else if (kbmap_queue.size()) {
			for (i = 0; i < kbmap_queue.size(); i++) {
				Uint16 value = (Uint16)kbmap_queue[i];

				// Send key down...
				id++;
				count++;
				timestamp = (SDL_GetTicks() - ticks) / 16;

				statePad[((value & 0xff00) >> 8)] |=
					((Uint8)(value & 0x00ff));

				SendPadState(statePad, id, count, timestamp, headers);

				// Sleep...
				SDL_Delay(50);

				// Send key up...
				id++;
				count++;
				timestamp = (SDL_GetTicks() - ticks) / 16;	

				statePad[((value & 0xff00) >> 8)] &=
					~((Uint8)(value & 0x00ff));

				SendPadState(statePad, id, count, timestamp, headers);

				// Sleep...
				SDL_Delay(50);
			}
			kbmap_queue.clear();
		}
	}

	// Never reached...
	return 0;
}

Sint32 OpenRemotePlay::SessionPerform(void)
{
	SetCaption("Connecting...");

	CURL *curl = curl_easy_init();

	ostringstream os;
	os << "http://";
	os << config.ps3_addr << ":" << config.ps3_port;
	os << ORP_GET_SESSION;

	curl_easy_setopt(curl, CURLOPT_URL, os.str().c_str());
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, orpCurlDebug);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, ORP_USER_AGENT);

	vector<struct orpHeaderValue_t *> headerList;
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&headerList);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, orpParseResponseHeader);

	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0);
	curl_easy_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0);

	struct curl_slist *headers = NULL;

	Base64 base64;
	Uint8 *encoded;

	try {
		os.str("");
		os << "Host:";
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << "Accept: */*;q=0.01";
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << "Accept-Encoding:\"\"";
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << "Accept-Charset: iso-8859-1;q=0.01";
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << "Host: " << config.ps3_addr << ":" << config.ps3_port;
		headers = curl_slist_append(headers, os.str().c_str());

		encoded = base64.Encode(config.key.psp_id, ORP_KEY_LEN);
		if (!encoded) throw -1;
		os.str("");
		os << orpGetHeader(HEADER_PSPID);
		os << ": " << encoded;
		delete [] encoded;
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << orpGetHeader(HEADER_VERSION);
		os << ": " << ORP_PREMO_VMAJOR << "." << ORP_PREMO_VMINOR;
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << orpGetHeader(HEADER_MODE);
		os << ": " << "PREMO";
		//os << ": " << "REMOCON";
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << orpGetHeader(HEADER_PLATFORM_INFO);
		os << ": " << "PSP";
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << orpGetHeader(HEADER_PAD_INFO);
		os << ": " << "PSP-Pad";
		headers = curl_slist_append(headers, os.str().c_str());

		if (!(encoded = base64.Encode((const Uint8 *)config.psp_owner)))
			throw -1;

		os.str("");
		os << orpGetHeader(HEADER_USERNAME);
		os << ": " << encoded;
		delete [] encoded;
		headers = curl_slist_append(headers, os.str().c_str());

		os.str("");
		os << orpGetHeader(HEADER_TRANS);
		os << ": " << "capable";
		headers = curl_slist_append(headers, os.str().c_str());

		// PSP with video-out capability?
		//os.str("");
		//os << orpGetHeader(HEADER_VIDEO_OUT_CTRL);
		//os << ": " << "capable";
		//headers = curl_slist_append(headers, os.str().c_str());

		if (config.net_public) {
			if (!(encoded = base64.Encode((const Uint8 *)config.psn_login)))
				throw -1;

			os.str("");
			os << orpGetHeader(HEADER_SIGNINID);
			os << ": " << encoded;
			delete [] encoded;
			headers = curl_slist_append(headers, os.str().c_str());
		}

		os.str("");
		os << "Connection: Keep-Alive";
		headers = curl_slist_append(headers, os.str().c_str());

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	} catch (Sint32 e) {
		curl_slist_free_all(headers);
		return e;
	}

	CURLcode cc;
	cc = curl_easy_perform(curl);

	Uint32 code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	if (cc != 0 || code != 200) {
		if (cc != 0) DisplayError("Connection error!");
		else {
			os.str("");
			os << "Connection error: ";
			os << orpGetHeaderValue(HEADER_APP_REASON, headerList);
			DisplayError(os.str().c_str());
		}
		return -1;
	}

	session_id = orpGetHeaderValue(HEADER_SESSIONID, headerList);
	exec_mode = orpGetHeaderValue(HEADER_EXEC_MODE, headerList);
	if (!CreateKeys(orpGetHeaderValue(HEADER_NONCE, headerList))) return -1;
	if (config.net_public) {
		if (!CreateKeys(orpGetHeaderValue(HEADER_NONCE, headerList),
			orpAUTH_CHANGE_BITRATE)) return -1;
		if (!CreateKeys(orpGetHeaderValue(HEADER_NONCE, headerList),
			orpAUTH_SESSION_TERM)) return -1;
	}

	curl = curl_easy_init();

	os.str("");
	os << "http://";
	os << config.ps3_addr << ":" << config.ps3_port;
	os << ORP_GET_CTRL;

	curl_easy_setopt(curl, CURLOPT_URL, os.str().c_str());
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, orpCurlDebug);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, ORP_USER_AGENT);

	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0);
	curl_easy_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0);

	struct orpCtrlMode_t mode;
	mode.mode = CTRL_CHANGE_BITRATE;
	switch (config.bitrate) {
	case CTRL_BR_256:
		mode.param1 = "256000";
		break;
	case CTRL_BR_384:
		mode.param1 = "384000";
		break;
	case CTRL_BR_512:
		mode.param1 = "512000";
		break;
	case CTRL_BR_768:
		mode.param1 = "768000";
		break;
	case CTRL_BR_1024:
		mode.param1 = "1024000";
		break;
	}
	mode.param2 = "1024000";
	if (ControlPerform(curl, &mode) != 200) return -1;

	struct orpCodec_t *codec_video = GetCodec(
		orpGetHeaderValue(HEADER_VIDEO_CODEC, headerList));
	if (!codec_video) {
		orpPrintf("Required video codec not found: %s\n",
			orpGetHeaderValue(HEADER_VIDEO_CODEC, headerList));
		DisplayError("Video codec not found!");
		return -1;
	}
	struct orpCodec_t *codec_audio = GetCodec(
		orpGetHeaderValue(HEADER_AUDIO_CODEC, headerList));
	if (!codec_audio) {
		orpPrintf("Required audio codec not found: %s\n",
			orpGetHeaderValue(HEADER_AUDIO_CODEC, headerList));
		DisplayError("Audio codec not found!");
		return -1;
	}

	ps3_nickname = (char *)base64.Decode((const Uint8 *)
		orpGetHeaderValue(HEADER_PS3_NICKNAME, headerList));
	if (!ps3_nickname) ps3_nickname = strdup("Unknown");
	SetCaption(NULL);

	stream_audio = new orpStreamAudio(codec_audio);
	stream_audio->SetKeys(&config.key);
	stream_audio->SetClockFrequency(
		atoi(orpGetHeaderValue(HEADER_AUDIO_CLOCKFREQ, headerList)));
	stream_audio->SetChannels(
		atoi(orpGetHeaderValue(HEADER_AUDIO_CHANNELS, headerList)));
	stream_audio->SetSampleRate(
		atoi(orpGetHeaderValue(HEADER_AUDIO_SAMPLERATE, headerList)));

	// XXX: This is interesting?  Setting the audio bit-rate to 576000 works,
	// *but* it will cause the PS3 to crash (lock/unresponsive - even holding
	// down power) when exiting the premo server module.  So if you try to
	// launch a game, the PS3 will crash and can only be reset via the power
	// supply switch.  The same thing happens if you turn the PS3 off via the
	// Users menu, or by pressing circle on a PS3 controller/remote.  This bit-
	// rate is never used by the/ PSP, where the highest client-side bit-rate
	// is 128000.  See the header:
	// PREMO-Audio-Bitrate-Ability
	stream_audio->SetBitRate(576000);
	//stream_audio->SetBitRate(128000);

	// Default:
	//stream_audio->SetBitRate(
	//	atoi(orpGetHeaderValue(HEADER_AUDIO_BITRATE, headerList)));

	stream_video = new orpStreamVideo(codec_video);
	stream_video->SetView(&view);
	stream_video->SetKeys(&config.key);
	stream_video->SetClockFrequency(
		atoi(orpGetHeaderValue(HEADER_VIDEO_CLOCKFREQ, headerList)));
	stream_video->SetFrameDelay(
		strtod(orpGetHeaderValue(HEADER_VIDEO_FRAMERATE, headerList),
		(char **)NULL));

	stream_audio->SetSibling(stream_video);
	stream_video->SetSibling(stream_audio);

	os.str("");
	os << "http://";
	os << config.ps3_addr << ":" << config.ps3_port;
	os << ORP_GET_VIDEO;
	if (stream_video->Connect(config.ps3_addr, config.ps3_port,
		os.str(), session_id) != 0) return -1;

	SDL_Delay(50);

	os.str("");
	os << "http://";
	os << config.ps3_addr << ":" << config.ps3_port;
	os << ORP_GET_AUDIO;
	if (stream_audio->Connect(config.ps3_addr, config.ps3_port,
		os.str(), session_id) != 0) return -1;

	// Hang-out here until something happens...
	Sint32 result = SessionControl(curl);

	if (result == EVENT_RESTORE)
		orpPrintf("Session restore.\n");
	else
		orpPrintf("Session terminated.\n");

	// TODO: Free, clean-up everything, being really lazy here...
	SDL_CloseAudio();

	if (stream_video) delete stream_video;
	stream_video = NULL;
	if (stream_audio) delete stream_audio;
	stream_audio = NULL;

#ifdef ORP_DUMP_STREAM_HEADER
	if (videoConfig->h_header) fclose(videoConfig->h_header);
	if (audioConfig->h_header) fclose(audioConfig->h_header);
#endif
#ifdef ORP_DUMP_STREAM_DATA
	if (videoConfig->h_data) fclose(videoConfig->h_data);
	if (audioConfig->h_data) fclose(audioConfig->h_data);
#endif
#ifdef ORP_DUMP_STREAM_RAW
	if (videoConfig->h_raw) fclose(videoConfig->h_raw);
	if (audioConfig->h_raw) fclose(audioConfig->h_raw);
#endif
	return result;
}

void OpenRemotePlay::DisplayError(const char *text)
{
	SDL_WM_SetCaption("Error!", NULL);

	SDL_RWops *rw;
	SDL_Surface *icon = NULL;
	if ((rw = SDL_RWFromConstMem(error_png, error_png_len))) {
		icon = IMG_Load_RW(rw, 0);
		SDL_FreeRW(rw);
	}

	SDL_Color color;
	color.r = color.g = color.b = 0;
	SDL_Surface *surface = TTF_RenderUTF8_Blended(font_normal, text, color);

	int width = 0;
	SDL_Rect pos;
	memset(&pos, 0, sizeof(SDL_Rect));

	if (icon) width = icon->w + 4;
	if (surface) width += surface->w;
	if (width < ORP_FRAME_WIDTH)
		pos.x = (ORP_FRAME_WIDTH - width) / 2;
	pos.y = 218;

	SDL_LockMutex(view.lock);
	if (view.overlay) {
		SDL_FreeYUVOverlay(view.overlay);
		view.overlay = NULL;
	}
	if (view.size != VIEW_NORMAL) {
		view.size = VIEW_NORMAL;
		CreateView();
	}
	SDL_BlitSurface(splash, NULL, view.view, NULL);
	if (icon && surface) {
		SDL_Rect rect;
		rect.x = pos.x;
		pos.x += icon->w + 4;
		rect.y = pos.y;
		rect.w = icon->w;
		rect.h = icon->h;
		if (icon->h > surface->h)
			rect.y -= (icon->h - surface->h) / 2;
		else if (icon->h < surface->h)
			rect.y += (surface->h - icon->h) / 2;
		SDL_BlitSurface(icon, NULL, view.view, &rect);
		SDL_FreeSurface(icon);
	}
	if (surface) {
		SDL_Rect rect;
		rect.x = pos.x;
		rect.y = pos.y;
		rect.w = surface->w;
		rect.h = surface->h;
		SDL_BlitSurface(surface, NULL, view.view, &rect);
		SDL_FreeSurface(surface);
	}
	SDL_UpdateRect(view.view, 0, 0, 0, 0);
	SDL_UnlockMutex(view.lock);

	SDL_Event event;
	while (SDL_PollEvent(&event) > 0);
	while (SDL_WaitEvent(&event) > 0) {
		if (event.type == SDL_QUIT || (event.type == SDL_KEYDOWN &&
			event.key.keysym.sym == SDLK_q &&
			event.key.keysym.mod & (KMOD_LCTRL | KMOD_RCTRL))) {
			break;
		}
	}
}

void OpenRemotePlay::UpdateOverlay(void)
{
	SDL_Color color;
	color.r = color.g = color.b = 255;
	SDL_Surface *surface = NULL;

	if (font_normal) {
		surface = TTF_RenderUTF8_Blended(font_normal,
			os_caption.str().c_str(), color);
	}
	if (!surface) return;

	SDL_Rect rect;
	rect.x = rect.y = 0;
	rect.w = view.status_bg->w;
	rect.h = view.status_bg->h;
	SDL_FillRect(view.status_bg, &rect,
		SDL_MapRGBA(surface->format, 0, 0, 0, 128));
	if (mode_game && !strncasecmp(exec_mode.c_str(), "gam", 3)) {
		rect.w = mode_game->w;
		rect.h = mode_game->h;
		SDL_BlitSurface(mode_game, NULL, view.status_bg, &rect);
	}
	else if (mode_ps1 && !strncasecmp(exec_mode.c_str(), "ps1", 3)) {
		rect.w = mode_ps1->w;
		rect.h = mode_ps1->h;
		SDL_BlitSurface(mode_ps1, NULL, view.status_bg, &rect);
	}
	else if (mode_vsh && !strncasecmp(exec_mode.c_str(), "vsh", 3)) {
		rect.w = mode_vsh->w;
		rect.h = mode_vsh->h;
		SDL_BlitSurface(mode_vsh, NULL, view.status_bg, &rect);
	}

	rect.x = ORP_OVERLAY_HEIGHT + 2;
	rect.y = (ORP_OVERLAY_HEIGHT - surface->h) / 2;
	rect.w = surface->w;
	rect.h = surface->h;
	SDL_BlitSurface(surface, NULL, view.status_bg, &rect);
#if 0
	surface = TTF_RenderUTF8_Blended(font_small,
		exec_mode.c_str(), color);
	if (!surface) return;
	rect.w = surface->w;
	rect.h = surface->h;
	rect.x = view.status_bg->w - surface->w;
	SDL_BlitSurface(surface, NULL, view.status_bg, &rect);
#endif
	ConvertRGBtoYUV(view.status_bg, view.status_yuv);
	view.status_ticks = SDL_GetTicks() + 2000;
}

// vi: ts=4
