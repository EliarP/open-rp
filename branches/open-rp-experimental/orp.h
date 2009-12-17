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

#ifndef _ORP_H
#define _ORP_H

using namespace std;

#include <curl/curl.h>

#include <openssl/aes.h>

#include <SDL.h>
#include <SDL_thread.h>
#include <SDL_image.h>
#include <SDL_net.h>
#include <SDL_ttf.h>

extern "C" {
#include <libavutil/avutil.h>
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
};

#include <string>
#include <vector>
#include <queue>

#include "yuv.h"
#include "config.h"

#define ORP_PREMO_VMAJOR	0
#define ORP_PREMO_VMINOR	3

#define ORP_FRAME_WIDTH		480
#define ORP_FRAME_HEIGHT	272
#define ORP_OVERLAY_HEIGHT	32
#define ORP_SESSION_LEN		16
#define ORP_PADSTATE_MAX	60
#define ORP_PADSTATE_LEN	128
#define ORP_AUDIO_BUF_LEN 	1024

#define ORP_USER_AGENT		"premo/1.0.0 libhttp/1.0.0"

#define ORP_GET_SESSION		"/sce/premo/session"
#define ORP_GET_CTRL		"/sce/premo/session/ctrl"
#define ORP_GET_VIDEO		"/sce/premo/session/video"
#define ORP_GET_AUDIO		"/sce/premo/session/audio"
#define ORP_POST_PAD		"/sce/premo/session/pad"

// PSP PAD offsets and bits
#define ORP_PAD_PSP_HOME	0x0101
#define ORP_PAD_PSP_SELECT	0x0501
#define ORP_PAD_PSP_L3		0x0502
#define ORP_PAD_PSP_R3		0x0504
#define ORP_PAD_PSP_START	0x0508
#define ORP_PAD_PSP_DPUP	0x0510
#define ORP_PAD_PSP_DPRIGHT	0x0520
#define ORP_PAD_PSP_DPDOWN	0x0540
#define ORP_PAD_PSP_DPLEFT	0x0580
#define ORP_PAD_PSP_R2		0x0701
#define ORP_PAD_PSP_L2		0x0702
#define ORP_PAD_PSP_L1		0x0704
#define ORP_PAD_PSP_R1		0x0708
#define ORP_PAD_PSP_TRI		0x0710
#define ORP_PAD_PSP_CIRCLE	0x0720
#define ORP_PAD_PSP_X		0x0740
#define ORP_PAD_PSP_SQUARE	0x0780
#define ORP_PAD_PSP_RXAXIS	0x08
#define ORP_PAD_PSP_RYAXIS	0x0a
#define ORP_PAD_PSP_LXAXIS	0x0c
#define ORP_PAD_PSP_LYAXIS	0x0e

#define ORP_DS3_SELECT		0x00
#define ORP_DS3_L3			0x01
#define ORP_DS3_R3			0x02
#define ORP_DS3_START		0x03
#define ORP_DS3_DPUP		0x04
#define ORP_DS3_DPRIGHT		0x05
#define ORP_DS3_DPDOWN		0x06
#define ORP_DS3_DPLEFT		0x07
#define ORP_DS3_L2			0x08
#define ORP_DS3_R2			0x09
#define ORP_DS3_L1			0x0a
#define ORP_DS3_R1			0x0b
#define ORP_DS3_TRI			0x0c
#define ORP_DS3_CIRCLE		0x0d
#define ORP_DS3_X			0x0e
#define ORP_DS3_SQUARE		0x0f
#define ORP_DS3_HOME		0x10

#define ORP_PAD_TIMESTAMP	0x40
#define ORP_PAD_EVENTID		0x48

#define ORP_PAD_KEYUP		0x10000000
#define ORP_PAD_KEYDOWN		0x20000000

#define ORP_SRCH_REPLIES	5
#define ORP_SRCH_TIMEOUT	30

// UDP broadcast from PSP to *:9293
#define ORP_ANNOUNCE_SRCH	"SRCH"

struct PktAnnounceSrch_t {
	Uint8 id[4];
};

#define CreatePktAnnounceSrch(pkt) \
	memcpy(pkt.id, ORP_ANNOUNCE_SRCH, 4);

// UDP reply from PlayStation 3, 156 bytes
#define ORP_ANNOUNCE_RESP	"RESP"

struct PktAnnounceResp_t {
	Uint8 id[4];				// 4
	Uint8 unk0[6];				// 10
	Uint8 ps3_mac[ORP_MAC_LEN];	// 16
	Uint8 ps3_nickname[ORP_NICKNAME_LEN];
								// 144
#define ORP_PS3_NPX_LEN		12
	Uint8 npx[ORP_PS3_NPX_LEN];
								// 156
};

enum orpHeader {
	HEADER_NULL,

	HEADER_APP_REASON,
	HEADER_AUDIO_BITRATE,
	HEADER_AUDIO_BITRATE_ABILITY,
	HEADER_AUDIO_CHANNELS,
	HEADER_AUDIO_CLOCKFREQ,
	HEADER_AUDIO_CODEC,
	HEADER_AUDIO_CONFIG,
	HEADER_AUDIO_SAMPLERATE,
	HEADER_AUTH,
	HEADER_CTRL_BITRATE,
	HEADER_CTRL_MAXBITRATE,
	HEADER_CTRL_MODE,
	HEADER_EXEC_MODE,
	HEADER_MODE,
	HEADER_NONCE,
	HEADER_OTA,
	HEADER_PAD_ASSIGN,
	HEADER_PAD_COMPLETE,
	HEADER_PAD_INDEX,
	HEADER_PAD_INFO,
	HEADER_PLATFORM_INFO,
	HEADER_POWER_CONTROL,
	HEADER_PS3_NICKNAME,
	HEADER_PSPID,
	HEADER_SESSIONID,
	HEADER_SIGNINID,
	HEADER_TRANS,
	HEADER_TRANS_MODE,
	HEADER_USERNAME,
	HEADER_VERSION,
	HEADER_VIDEO_BITRATE,
	HEADER_VIDEO_BITRATE_ABILITY,
	HEADER_VIDEO_CLOCKFREQ,
	HEADER_VIDEO_CODEC,
	HEADER_VIDEO_CONFIG,
	HEADER_VIDEO_FRAMERATE,
	HEADER_VIDEO_FRAMERATE_ABILITY,
	HEADER_VIDEO_OUT_CTRL,
	HEADER_VIDEO_RESOLUTION,
	HEADER_VIDEO_RESOLUTION_ABILITY,
};

struct orpHeader_t {
	enum orpHeader header;
	string name;
};

struct orpHeaderValue_t {
	enum orpHeader header;
	string value;
};

enum orpCtrlMode {
	CTRL_CHANGE_BITRATE,
	CTRL_SESSION_TERM,

	CTRL_NULL,
};

struct orpCtrlMode_t {
	enum orpCtrlMode mode;
	string param1;
	string param2;
};

enum orpCtrlBitrate {
	CTRL_BR_256,
	CTRL_BR_384,
	CTRL_BR_512,
	CTRL_BR_768,
	CTRL_BR_1024
};

#define ORP_KBMAP_LEN	60
#define ORP_KBMAP_SX	4
#define ORP_KBMAP_SY	2

struct orpKeyboardMap_t {
	SDLKey sym;
	Uint32 mod;
	Sint8 x;
	Sint8 y;
};

enum orpEvent {
	EVENT_ERROR,
	EVENT_RESTORE,
	EVENT_SHUTDOWN,
	EVENT_STREAM_EXIT
};

enum orpViewSize {
	VIEW_NORMAL,
	VIEW_MEDIUM,
	VIEW_LARGE,
	VIEW_FULLSCREEN
};

struct orpView_t {
	enum orpViewSize size;
	enum orpViewSize prev;
	SDL_Surface *view;
	SDL_Overlay *overlay;
	SDL_Surface *status_bg;
	SDL_YUVSurface *status_yuv;
	Uint32 status_ticks;
	bool status_sticky;
	SDL_Rect fs;
	SDL_Rect scale;
	SDL_Rect desktop;
	SDL_mutex *lock;
};

enum orpAuthType {
	orpAUTH_NORMAL,
	orpAUTH_CHANGE_BITRATE,
	orpAUTH_SESSION_TERM
};

struct orpKey_t {
	Uint8 skey0[ORP_KEY_LEN];
	Uint8 skey1[ORP_KEY_LEN];
	Uint8 skey2[ORP_KEY_LEN];
	Uint8 psp_id[ORP_KEY_LEN];
	Uint8 pkey[ORP_KEY_LEN];
	Uint8 xor_pkey[ORP_KEY_LEN];
	Uint8 nonce[ORP_KEY_LEN];
	Uint8 xor_nonce[ORP_KEY_LEN];
	Uint8 iv1[ORP_KEY_LEN];

	Uint8 *auth_normal;
	Uint8 *auth_change_bitrate;
	Uint8 *auth_session_term;
};

struct orpConfig_t {
	Uint8 ps3_mac[ORP_MAC_LEN];
	char psp_owner[ORP_NICKNAME_LEN];
	Uint8 psp_mac[ORP_MAC_LEN];
	char ps3_addr[ORP_HOSTNAME_LEN];
	Uint16 ps3_port;
	bool ps3_search;
	bool ps3_wolr;
	bool net_public;
	struct orpKey_t key;
	char psn_login[ORP_NICKNAME_LEN];
	enum orpCtrlBitrate bitrate;
};

struct orpStreamPacketHeader_t {
	Uint8 magic[2];	// 2
	Uint16 frame;	// 4
	Uint32 clock;	// 8
	Uint8 root[4];	// 12
	Uint16 unk2;	// 14
	Uint16 unk3;	// 16
	Uint16 len;		// 18
	Uint16 unk4;	// 20
	Uint16 unk5;	// 22
	Uint16 unk6;	// 24
	Uint16 unk7;	// 26
	Uint16 unk8;	// 28
	Uint16 unk9;	// 30
	Uint16 unk10;	// 32
};

struct orpStreamPacket_t {
	Uint32 clock;
	struct orpStreamPacketHeader_t header;
	AVPacket pkt;
};

struct orpCodec_t {
	string name;
	AVCodec *codec;
};

enum orpStreamType {
	ST_AUDIO,
	ST_VIDEO
};

class orpStreamBase;
class orpStreamBuffer {
public:
	orpStreamBuffer();
	~orpStreamBuffer();

	void Push(orpStreamBase *stream, struct orpStreamPacket_t *packet);
	struct orpStreamPacket_t *Pop(void);

	orpStreamBuffer *GetSibling(void) { return sibling; };
	void Broadcast(void) { SDL_CondBroadcast(cond_buffer_ready); };
	Sint32 WaitOnBuffer(void) {
		SDL_LockMutex(lock_buffer_ready);
		SDL_CondWait(cond_buffer_ready, lock_buffer_ready);
		SDL_UnlockMutex(lock_buffer_ready); return 0; };

	Uint32 GetClock(Uint32 &clock);
	Uint32 GetDuration(Uint32 &duration);
	Uint32 UpdateDuration(void);
	bool IsBufferReady(void) {
		if (GetDuration(duration) > period) return true;
		return false; };
	bool IsBufferEmpty(void) {
		if (GetDuration(duration) == 0) return true;
		return false; };

	Uint32 len;
	Uint32 pos;
	Uint8 *data;

protected:
	friend class orpStreamBase;

	Uint32 clock;
	Uint32 base;
	Uint32 duration;
	Uint32 period;
	queue<struct orpStreamPacket_t *> pkt;
	orpStreamBuffer *sibling;
	SDL_mutex *lock;
	SDL_cond *cond_buffer_ready;
	SDL_mutex *lock_buffer_ready;
};

class orpStreamBase
{
public:
	orpStreamBase(orpStreamType type, struct orpCodec_t *codec);
	~orpStreamBase();

	void SetKeys(const struct orpKey_t *key);
	void SetClockFrequency(Uint32 freq) { clock_freq = freq; };
	void SetSibling(orpStreamBase *sibling) {
		this->sibling = sibling;
		buffer->sibling = sibling->GetBuffer(); };

	const char *GetHost(void) { return url.c_str(); };
	Uint16 GetPort(void) { return port; };
	const char *GetUrl(void) { return url.c_str(); };
	const char *GetSessionId(void) { return session_id.c_str(); };
	Uint32 GetClockFrequency(void) { return clock_freq; };
	orpStreamBuffer *GetBuffer(void) { return buffer; };
	const char *GetCodecName(void) { return codec->name.c_str(); };
	const char *GetAuthKey(orpAuthType type = orpAUTH_NORMAL);
	struct orpKey_t *GetKeys(void) { return &key; };
	AES_KEY *GetDecryptKey(void) { return &aes_key; };
	orpStreamType GetType(void) { return type; };
	orpStreamBase *GetSibling(void) { return sibling; };
	orpStreamType GetSiblingType(void) { return sibling->GetType(); };
	Uint32 GetClock(Uint32 &clock) { return buffer->GetClock(clock); };
	Uint32 GetDuration(Uint32 &duration) { return buffer->GetDuration(duration); };
	Uint32 GetSiblingClock(Uint32 &clock) { return sibling->GetClock(clock); };
	Uint32 GetSiblingDuration(Uint32 &duration) { return sibling->GetDuration(duration); };

	virtual Sint32 Connect(string host, Uint16 port, string url, string session_id);

protected:
	orpStreamType type;
	struct orpCodec_t *codec;
	string host;
	Uint16 port;
	string url;
	string session_id;
	Uint32 clock_freq;
	AES_KEY aes_key;
	struct orpKey_t key;
	orpStreamBuffer *buffer;
	SDL_Thread *thread_connection;
	orpStreamBase *sibling;
};

class orpStreamAudio : public orpStreamBase
{
public:
	orpStreamAudio(struct orpCodec_t *codec);
	~orpStreamAudio();

	void SetChannels(Sint32 channels) { this->channels = channels; };
	void SetSampleRate(Sint32 rate) { sample_rate = rate; };
	void SetBitRate(Sint32 rate) { bit_rate = rate; };

	Sint32 GetChannels(void) { return channels; };
	Sint32 GetSampleRate(void) { return sample_rate; };
	Sint32 GetBitRate(void) { return bit_rate; };
	AVCodecContext *GetContext(void) { return context; };

	Sint32 InitDevice(void);
	Sint32 InitDecoder(void);
	void CloseDevice(void);
	void CloseDecoder(void);

	Sint32 Connect(string host, Uint16 port, string url, string session_id);

protected:
	Sint32 channels;
	Sint32 sample_rate;
	Sint32 bit_rate;
	AVCodecContext *context;
};

class orpStreamVideo : public orpStreamBase
{
public:
	orpStreamVideo(struct orpCodec_t *codec);
	~orpStreamVideo();

	void SetView(struct orpView_t *view) { this->view = view; };
	void SetFrameDelay(double rate) { frame_delay = (Uint32)(1000.0 / rate); };

	struct orpView_t *GetView(void) { return view; };
	Uint32 GetFrameDelay(void) { return frame_delay; };
	AVCodecContext *GetContext(void) { return context; };

	Sint32 InitDecoder(void);
	void CloseDecoder(void);

	void ScaleFrame(AVFrame *f);

	Sint32 Connect(string host, Uint16 port, string url, string session_id);

	void Terminate(bool terminate) { this->terminate = terminate; };
	bool ShouldTerminate(void) { return terminate; };

protected:
	Uint32 frame_delay;
	struct orpView_t *view;
	AVCodecContext *context;
	struct SwsContext *sws_normal;
	struct SwsContext *sws_medium;
	struct SwsContext *sws_large;
	struct SwsContext *sws_fullscreen;
	SDL_Thread *thread_decode;
	bool terminate;
};

class OpenRemotePlay
{
public:
	OpenRemotePlay(struct orpConfig_t *config);
	~OpenRemotePlay();

	bool SessionCreate(void);
	void SessionDestroy(void);

protected:
	bool terminate;
	struct orpConfig_t config;
	vector<struct orpCodec_t *> codec;
	struct orpView_t view;
	orpStreamVideo *stream_video;
	orpStreamAudio *stream_audio;

	string session_id;
	char *ps3_nickname;
	ostringstream os_caption;
	string exec_mode;

	SDL_Joystick *js;

	TCPsocket skt_pad;
	TTF_Font *font_small;
	TTF_Font *font_normal;
	SDL_Surface *splash;
	SDL_Surface *mode_game;
	SDL_Surface *mode_ps1;
	SDL_Surface *mode_vsh;
	Uint32 rmask, gmask, bmask, amask;

	bool CreateView(void);
	bool CreateKeys(const string &nonce,	
		enum orpAuthType type = orpAUTH_NORMAL);
	bool SetCaption(const char *caption);
	struct orpCodec_t *GetCodec(const string &name);
	Sint32 ControlPerform(CURL *curl, struct orpCtrlMode_t *mode);
	Sint32 SendPadState(Uint8 *pad, Uint32 id,
		Uint32 &count, Uint32 timestamp, vector<string> &headers);
	Sint32 SessionControl(CURL *curl);
	Sint32 SessionPerform(void);
	void DisplayError(const char *text);
	void UpdateOverlay(void);
};

#endif // _ORP_H
// vi: ts=4
