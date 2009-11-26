#ifndef _ORPAV_H
#define _ORPAV_H

using namespace std;

class orpStreamBuffer {
public:
	orpStreamBuffer();
	~orpStreamBuffer();

	void Push(struct orpStreamPacket_t *pkt);
	struct orpStreamPacket_t *Pop(void);

	Uint32 GetClock(void) { return clock; };
	void ResetClock(void) { clock = 0; };

	void Lock(void);
	void Unlock(void);

	Uint32 len;
	Uint32 pos;
	Uint8 *data;

	orpStreamBuffer *sibling;

protected:
	Uint32 clock;
	SDL_mutex *lock;
	queue<struct orpStreamPacket_t *> pkt;
	Uint32 period;
};

class orpStreamBase
{
public:
	orpStreamBase(orpStreamType type, struct orpCodec_t *codec);
	~orpStreamBase();

	void SetKeys(struct orpKey_t *key);
	void SetClockFrequency(Uint32 freq) { clock_freq = freq; };
	void SetSiblingBuffer(orpStreamBase *sibling) { buffer->sibling = sibling->GetBuffer(); };

	void Connect(string host, Uint16 port, string url, string session_id);

	string GetHost(void) { return host; };
	Uint16 GetPort(void) { return port; };
	string GetUrl(void) { return url; };
	string GetSessionId(void) { return session_id; };
	Uint32 GetClockFrequency(void) { return clock_freq; };
	orpStreamBuffer *GetBuffer(void) { return buffer; };

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
	SDL_Thread *thread_decode;
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

protected:
	Sint32 channels;
	Sint32 sample_rate;
	Sint32 bit_rate;
};

class orpStreamVideo : public orpStreamBase
{
public:
	orpStreamVideo(struct orpCodec_t *codec);
	~orpStreamVideo();

	void SetFrameDelay(float rate) { frame_delay = (Uint32)(1000.0f / rate); };

	Uint32 GetFrameDelay(void) { return frame_delay; };

protected:
	Uint32 frame_delay;
};

#endif // _ORP_H
// vi: ts=4
