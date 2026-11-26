#include "communication.hpp"
#include <EEPROM.h>   // small amount of flash that behaves like non-volatile memory
#include <string.h>   // memset(), memcpy()

// ============================================================================
// EEPROM = " Electrically Erasable Programmable Read-Only Memory". It keeps its
// contents when power is removed. On the AVR boards it is a small EEPROM region.
//
// We store TWO 2-byte values:
//   address 0..1 : a "magic number" 0xE290. It is just a recognizable pattern.
//                  If we read it back, we know a valid record was written here
//                  before (rather than random erased-flash bytes).
//   address 2..3 : the boot epoch (a counter incremented on every power-on).
//
// WHY BOTHER? The epoch is part of the encryption nonce. If we restarted at 0
// after every reboot, we would eventually reuse the same (key, nonce) pair,
// which is catastrophic for ChaCha20-Poly1305. Persisting it avoids that.
//
// `static const` here means "one constant value private to this .cpp file".
// ============================================================================
static const int EEPROM_MAGIC_ADDR = 0;
static const int EEPROM_EPOCH_ADDR = 2;
static const uint16_t EEPROM_MAGIC  = 0xE290;

// ---------------------------------------------------------------------------
// Constructor. The long list after ':' is a "member initializer list": it sets
// every member variable to a known starting value BEFORE the constructor body
// runs. `nullptr` means "no function registered yet" for our callbacks.
// ---------------------------------------------------------------------------
Communication::Communication(Encryption &crypto, ILink &link)
    : _crypto(crypto), _link(&link), _onMessage(nullptr), _onEvent(nullptr),
      _epoch(1), _ctr(0), _lastRxEpoch(0), _lastRxCtr(0), _haveRx(false),
      _txState(TX_IDLE), _attempt(0), _busyCount(0), _txLen(0),
      _txEpoch(0), _txCtr(0), _deadline(0),
      _ackPending(false), _ackDeadline(0),
      _haveAck(false), _ackEpoch(0), _ackCtr(0)
{
    // memset() fills a block of memory with zeroes. Starting with clean buffers
    // makes debugging easier, and means no stray bytes are ever transmitted.
    memset(_txPacket, 0, sizeof(_txPacket));
    memset(_rxBuf, 0, sizeof(_rxBuf));
    memset(_ackPacket, 0, sizeof(_ackPacket));
}

// Called once from setup(): remember the callbacks and load the boot counter.
void Communication::begin(MessageHandler onMessage, EventHandler onEvent) {
    _onMessage = onMessage;
    _onEvent = onEvent;
    _loadEpoch();
    _ctr = 0;              // first message this boot will be numbered 1
    _txState = TX_IDLE;
    _ackPending = false;
    _haveAck = false;
    _haveRx = false;
}

// ---------------------------------------------------------------------------
// EEPROM epoch handling
// ---------------------------------------------------------------------------
void Communication::_loadEpoch() {
    uint16_t magic = 0;
    uint16_t stored = 0;

    // EEPROM.get(address, variable) reads sizeof(variable) bytes into variable.
    EEPROM.get(EEPROM_MAGIC_ADDR, magic);
    if (magic == EEPROM_MAGIC) EEPROM.get(EEPROM_EPOCH_ADDR, stored);

    // 0 means "nothing written yet". 0xFFFF is the largest possible uint16_t;
    // if we ever reach it we wrap around to 1 rather than overflow to 0.
    if (stored == 0 || stored == 0xFFFF) _epoch = 1;
    else _epoch = (uint16_t)(stored + 1);

    _saveEpoch(_epoch);   // save immediately so a crash can't reuse this value
}

void Communication::_saveEpoch(uint16_t epoch) {
    EEPROM.put(EEPROM_MAGIC_ADDR, EEPROM_MAGIC);
    EEPROM.put(EEPROM_EPOCH_ADDR, epoch);
}

// Pick a random delay between 50 and 400 ms. random(min, max) includes min and
// EXCLUDES max, so we pass max+1 to make the upper bound inclusive.
uint32_t Communication::_randomBackoff() const {
    return (uint32_t)random((long)CFG_BACKOFF_MIN_MS,
                            (long)CFG_BACKOFF_MAX_MS + 1L);
}

// ---------------------------------------------------------------------------
// Transmit path
// ---------------------------------------------------------------------------
bool Communication::send(const uint8_t *payload, uint8_t len) {
    // We can only hold ONE message in flight. If a retry sequence is already
    // underway, reject a second message rather than corrupting the first.
    if (_txState != TX_IDLE) return false;
    if (len > PROTO_MAX_PAYLOAD) return false;   // 24-byte payload limit

    // 1) Describe this message with a Header struct (see protocol.hpp).
    Header h;
    h.type  = PKT_DATA;             // this is a message, not an ACK
    h.src   = SELF_ID;              // our ID: 0x0A or 0x0B (see config.hpp)
    h.epoch = _epoch;               // boot number from EEPROM
    h.ctr   = (uint16_t)(++_ctr);   // increment first, then use: 1, 2, 3...
    h.len   = len;                  // how many plaintext/ciphertext bytes

    // 2) Build the 12-byte nonce from the header. Both devices run the SAME
    //    function, so the receiver can rebuild the identical nonce for open().
    uint8_t nonce[PROTO_NONCE_LEN];
    buildNonce(h, nonce);

    // 3) Serialise the header into the first 7 bytes of the outgoing packet.
    packHeader(h, _txPacket);

    // 4) Encrypt. The result is laid out in memory as:
    //    [ 7-byte header ][ len bytes ciphertext ][ 16-byte tag ]
    //    `cipher` points just after the header; the tag goes after the cipher.
    uint8_t tag[PROTO_TAG_LEN];
    _crypto.seal(nonce, _txPacket, PROTO_HDR_LEN,
                 payload, len,
                 _txPacket + PROTO_HDR_LEN, tag, PROTO_TAG_LEN);
    memcpy(_txPacket + PROTO_HDR_LEN + len, tag, PROTO_TAG_LEN);

    // 5) Remember the total length and which (epoch, ctr) we used, so an ACK
    //    can be matched later. Then move the state machine to PENDING.
    _txLen = (uint8_t)(PROTO_HDR_LEN + len + PROTO_TAG_LEN);
    _txEpoch = h.epoch;
    _txCtr = h.ctr;
    _attempt = 0;
    _busyCount = 0;
    _txState = TX_PENDING;
    return true;
}

// Text is just bytes. This wrapper measures the string and forwards it.
bool Communication::sendText(const char *text) {
    if (!text) return false;             // nullptr means "no string"
    size_t n = strlen(text);             // length WITHOUT the trailing '\0'
    if (n > PROTO_MAX_PAYLOAD) return false;
    return send((const uint8_t *)text, (uint8_t)n);
}

// Actually transmit. Called only when the medium is clear.
void Communication::_sendFrame() {
    _event(COMM_TX_START, _attempt);     // tell the host "we are sending"
    _link->send(_txPacket, _txLen);      // BLOCKING: returns when frame is sent

    // How long should we wait for an ACK?
    //   time for the ACK to travel on the medium
    // + time for it to reach us and be decoded (twice: there and back)
    // + a safety margin.
    // Different links (IR vs Wi-Fi) supply their own numbers via ILink.
    uint32_t timeout = _link->airtimeMs(PROTO_ACK_PACKET)
                     + 2UL * _link->latencyMs()
                     + CFG_ACK_MARGIN_MS;
    if (timeout < 50UL) timeout = 50UL;   // avoid a zero/very tiny timeout
    _deadline = millis() + timeout;       // millis() is a ms counter since boot
    _txState = TX_WAIT_ACK;
}

void Communication::_fail() {
    _txState = TX_IDLE;                   // free the engine for the next message
    _event(COMM_TX_FAIL, _attempt);       // report to the host
}

// ---------------------------------------------------------------------------
// Receive path
// ---------------------------------------------------------------------------
// Build the ACK for a DATA packet we just accepted.
void Communication::_queueAck(const Header &acked) {
    Header a;
    a.type  = PKT_ACK;
    a.src   = SELF_ID;         // the ACKER's ID, not the original sender's
    a.epoch = acked.epoch;     // echo the DATA packet's counters so the sender
    a.ctr   = acked.ctr;       // can tell exactly which message we acknowledge
    a.len   = 0;               // ACKs carry no payload: header + tag = 23 bytes

    packHeader(a, _ackPacket);
    uint8_t nonce[PROTO_NONCE_LEN];
    buildNonce(a, nonce);      // type=ACK makes this nonce different from DATA's

    uint8_t tag[PROTO_TAG_LEN];
    const uint8_t emptyPayload = 0;   // valid pointer, zero length
    // seal() with len=0 exercises the ACK path. The SELFTEST command checks
    // that this exact case round-trips correctly.
    _crypto.seal(nonce, _ackPacket, PROTO_HDR_LEN,
                 &emptyPayload, 0,
                 _ackPacket + PROTO_HDR_LEN, tag, PROTO_TAG_LEN);
    memcpy(_ackPacket + PROTO_HDR_LEN, tag, PROTO_TAG_LEN);

    // Remember which DATA this ACK answers. A lost ACK makes the sender retry
    // the identical DATA; we can then resend this cached ACK byte-for-byte.
    _haveAck = true;
    _ackEpoch = acked.epoch;
    _ackCtr = acked.ctr;

    // Don't transmit immediately: we might be in the middle of something, or
    // the medium might still be ringing. tick() sends it when it is safe.
    _ackPending = true;
    _ackDeadline = millis() + CFG_BACKOFF_MAX_MS;
}

// Poll the link ONCE per tick(). This is where all received frames are handled.
void Communication::_pollRx() {
    // `sizeof(_rxBuf)` is PROTO_MAX_PACKET + 8 (55). The link fills up to that
    // many bytes and returns
    // a count. That count is untrusted (the IR decoder can append stray bits),
    // so we never use it as the packet length.
    uint8_t n = _link->recv(_rxBuf, sizeof(_rxBuf));
    if (n == 0) return;                       // nothing arrived this time

    Header h;
    // Step 1: structural checks only (lengths, type values). This does NOT
    // check the cryptographic tag or who sent it.
    if (!unpackHeader(_rxBuf, n, h)) {
        _event(COMM_RX_REJECT, REJECT_MALFORMED);
        return;
    }
    // Step 2: trust only the one device we were paired with.
    if (h.src != PEER_ID) {
        _event(COMM_RX_REJECT, REJECT_WRONG_SRC);
        return;
    }

    // Step 3: replay protection. Counters must strictly increase. If an attacker
    // re-records and re-sends an old (valid) frame, we drop it here.
    // `epoch` is compared first because a new boot resets `ctr` to 1.
    //
    // EXCEPTION: an EXACT duplicate of the last accepted DATA is almost always
    // the sender retrying because OUR ACK was lost. We remember that case here,
    // but do NOT re-ACK until step 4 has verified the tag — otherwise a forged
    // header alone could make us transmit. Truly old counters are still dropped.
    bool isDuplicate = false;
    if (h.type == PKT_DATA && _haveRx &&
        (h.epoch < _lastRxEpoch ||
         (h.epoch == _lastRxEpoch && h.ctr <= _lastRxCtr))) {
        isDuplicate = (_haveAck && h.epoch == _ackEpoch && h.ctr == _ackCtr);
        if (!isDuplicate) {
            _event(COMM_RX_REJECT, REJECT_REPLAY);
            return;
        }
    }

    // Step 4: rebuild the nonce from the received header and verify+decrypt.
    uint8_t nonce[PROTO_NONCE_LEN];
    buildNonce(h, nonce);

    const uint8_t *cipher = _rxBuf + PROTO_HDR_LEN;  // skip the 7-byte header
    const uint8_t *tag = cipher + h.len;             // tag follows ciphertext
    uint8_t plain[PROTO_MAX_PAYLOAD];
    if (!_crypto.open(nonce, _rxBuf, PROTO_HDR_LEN,
                      cipher, h.len, tag, PROTO_TAG_LEN, plain)) {
        _event(COMM_RX_REJECT, REJECT_BAD_TAG);
        return;   // open() zeroes `plain` on failure, so nothing leaks out
    }

    // Valid retransmission: the payload is authentic but we already delivered
    // it once, so re-send the cached ACK and stop here. This is what lets the
    // sender recover from a lost ACK instead of reporting TX FAIL.
    if (isDuplicate) {
        _ackPending = true;
        _ackDeadline = millis() + CFG_BACKOFF_MAX_MS;
        return;
    }

    // Step 5a: if it is an ACK, it completes our pending send ONLY if its
    // echoed counters match the exact packet we are waiting for.
    if (h.type == PKT_ACK) {
        if (_txState == TX_WAIT_ACK &&
            h.epoch == _txEpoch && h.ctr == _txCtr) {
            _txState = TX_IDLE;
            _event(COMM_TX_OK, _attempt);
        }
        return;
    }

    // Step 5b: a valid DATA packet. Record its counters BEFORE calling the
    // callback, so even if the callback triggers another send, this packet
    // can never be accepted a second time.
    _lastRxEpoch = h.epoch;
    _lastRxCtr = h.ctr;
    _haveRx = true;
    _event(COMM_RX_OK, h.len);
    if (_onMessage) _onMessage(plain, h.len, h.src, h.epoch, h.ctr);
    _queueAck(h);
}

// ---------------------------------------------------------------------------
// Main state machine — one small decision per call.
// ---------------------------------------------------------------------------
void Communication::tick() {
    // Always listen first. An ACK may have arrived, or the peer may have sent
    // a brand-new message while we were waiting for our own ACK.
    _pollRx();

    // If we owe the peer an ACK, send it as soon as the medium is free. The
    // deadline stops us holding it forever if the medium never frees up.
    if (_ackPending) {
        if (_link->channelClear()) {
            _link->send(_ackPacket, PROTO_ACK_PACKET);
            _ackPending = false;
        } else if ((int32_t)(millis() - _ackDeadline) >= 0) {
            _ackPending = false;   // give up rather than block the protocol
        }
    }

    if (_txState == TX_IDLE) return;   // nothing else to do

    if (_txState == TX_BACKOFF) {
        // The cast to int32_t handles millis() wrapping around to 0 after
        // ~49 days. Subtraction in signed 32-bit gives the correct difference.
        if ((int32_t)(millis() - _deadline) >= 0) _txState = TX_PENDING;
        return;
    }

    if (_txState == TX_PENDING) {
        // Give up if the medium has been busy too many times in a row.
        if (_busyCount >= CFG_MAX_CHANNEL_BUSY) {
            _fail();
            return;
        }
        if (!_link->channelClear()) {
            _busyCount++;
            _deadline = millis() + _randomBackoff();
            _txState = TX_BACKOFF;
            return;
        }
        _sendFrame();   // clear channel -> transmit
        return;
    }

    // TX_WAIT_ACK: _pollRx() at the top may already have completed this send.
    if (_txState == TX_WAIT_ACK && (int32_t)(millis() - _deadline) >= 0) {
        if (_attempt >= CFG_MAX_RETRIES) {
            _fail();                      // out of attempts
        } else {
            _attempt++;
            _deadline = millis() + _randomBackoff();
            // We deliberately do NOT rebuild the packet. The same bytes and
            // same nonce are resent, which is safe: identical input to AEAD
            // produces identical output and reveals no information.
            _txState = TX_BACKOFF;
        }
    }
}
