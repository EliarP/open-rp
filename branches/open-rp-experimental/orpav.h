#ifndef _ORPAV_H
#define _ORPAV_H

using namespace std;

class orpStreamBase;
class orpStreamBuffer {
public:
	orpStreamBuffer();
	~orpStreamBuffer();

	void Push(orpStreamBase *stream, struct orpStreamPacket_t *packet);
	struct orpStreamPacket_t *Pop(void);

	orpStreamBuffer *GetSibling(void) { return sibling; };
	void Broadcast(void) { SDL_CondBroadcast(cond_buffer_full); };
	Sint32 WaitOnBuffer(void) {
		SDL_LockMutex(lock_buffer_full);
		SDL_CondWait(cond_buffer_full, lock_buffer_full);
		SDL_UnlockMutex(lock_buffer_full); };

	Uint32 GetClock(Uint32 &clock);
	Uint32 GetDuration(Uint32 &duration);
	Uint32 UpdateDuration(void);
	bool IsBufferFull(void) {
		if (GetDuration(duration) > period) return true;
		return false; };

	Uint32 len;
	Uint32 pos;
	Uint8 *data;

protected:
	friend class orpStreamBase;

	Uint32 clock;
	Uint32 duration;
	Uint32 period;
	queue<struct orpStreamPacket_t *> pkt;
	orpStreamBuffer *sibling;
	SDL_mutex *lock;
	SDL_cond *cond_buffer_full;
	SDL_mutex *lock_buffer_full;
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
	Uint32 GetSiblingClock(Uint32 &clock) { return sibling->GetClock(clock); };

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

#endif // _ORP_H
// vi: ts=4
