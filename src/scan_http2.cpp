/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/**
 *
 * scan_http2:
 * Splits a reassembled TCP flow that carries HTTP/2 (RFC 7540) into one
 * output file per HTTP/2 stream. The TCP layer is reassembled by tcpip;
 * this scanner walks the HTTP/2 frame sequence and writes the DATA frame
 * payload of every stream to a dedicated file.
 *
 * The scanner works on cleartext h2c streams (including the h2c prior
 * knowledge handshake) and on TCP flows that simply contain HTTP/2
 * frames; TLS-encrypted h2 traffic cannot be split without decryption.
 */

#include "config.h"

#include "tcpflow.h"
#include "tcpip.h"
#include "tcpdemux.h"

#include <fcntl.h>
#include <map>
#include <sstream>
#include <iomanip>
#include <string>

#define HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define HTTP2_PREFACE_LEN 24
#define HTTP2_FRAME_HDR_LEN 9

#define HTTP2_FRAME_DATA 0x0
#define HTTP2_FRAME_HEADERS 0x1
#define HTTP2_FRAME_PRIORITY 0x2
#define HTTP2_FRAME_RST_STREAM 0x3
#define HTTP2_FRAME_SETTINGS 0x4
#define HTTP2_FRAME_PUSH_PROMISE 0x5
#define HTTP2_FRAME_PING 0x6
#define HTTP2_FRAME_GOAWAY 0x7
#define HTTP2_FRAME_WINDOW_UPDATE 0x8
#define HTTP2_FRAME_CONTINUATION 0x9

#define HTTP2_FLAG_ACK 0x1
#define HTTP2_FLAG_END_STREAM 0x1
#define HTTP2_FLAG_PADDED 0x8
#define HTTP2_FLAG_PRIORITY 0x20

class http2_scanner {
    struct stream_state {
        stream_state():fd(-1),bytes(0),closed(false),path(){}
        int fd;
        uint64_t bytes;
        bool closed;
        std::string path;
    };

public:
    http2_scanner(const std::string &flow_path, std::stringstream *xml_stream)
        :base_path(flow_path),xmlstream(xml_stream),streams(){}

    ~http2_scanner(){
        close_all();
    }

    /* Returns true if the buffer looks like an HTTP/2 flow. */
    static bool looks_like_http2(const uint8_t *buf, size_t len)
    {
        if(len >= HTTP2_PREFACE_LEN &&
           memcmp(buf, HTTP2_PREFACE, HTTP2_PREFACE_LEN)==0){
            return true;
        }
        /* A bare SETTINGS frame (length 0, type 4, stream 0) is the
         * first frame of every HTTP/2 connection. */
        if(len >= HTTP2_FRAME_HDR_LEN &&
           buf[0]==0 && buf[1]==0 && buf[2]==0 &&
           buf[3]==HTTP2_FRAME_SETTINGS &&
           (buf[4] & ~HTTP2_FLAG_ACK)==0 &&
           (buf[8] & 0x80)==0){
            return true;
        }
        return false;
    }

    /* Parse the whole reassembled flow and emit one file per stream. */
    void parse(const uint8_t *buf, size_t len)
    {
        size_t offset = 0;
        if(len >= HTTP2_PREFACE_LEN &&
           memcmp(buf, HTTP2_PREFACE, HTTP2_PREFACE_LEN)==0){
            offset = HTTP2_PREFACE_LEN;
        }

        while(offset + HTTP2_FRAME_HDR_LEN <= len){
            uint32_t payload_len = (uint32_t(buf[offset]) << 16) |
                                   (uint32_t(buf[offset+1]) << 8) |
                                   uint32_t(buf[offset+2]);
            uint8_t type = buf[offset+3];
            uint8_t flags = buf[offset+4];
            uint32_t stream_id = ((uint32_t(buf[offset+6]) << 16) |
                                  (uint32_t(buf[offset+7]) << 8) |
                                  uint32_t(buf[offset+8])) & 0x7FFFFFFFu;
            size_t frame_start = offset + HTTP2_FRAME_HDR_LEN;
            if(frame_start + payload_len > len) break;   // truncated tail

            const uint8_t *payload = buf + frame_start;
            process_frame(type, flags, stream_id, payload, payload_len);
            offset = frame_start + payload_len;   // next frame header
        }
    }

private:
    http2_scanner(const http2_scanner &);
    http2_scanner &operator=(const http2_scanner &);

    const std::string base_path;
    std::stringstream *xmlstream;
    std::map<uint32_t, stream_state *> streams;

    std::string stream_path(uint32_t stream_id)
    {
        std::stringstream os;
        os << base_path << "-HTTP2STREAM-"
           << std::setw(3) << std::setfill('0') << stream_id;
        return os.str();
    }

    stream_state *get_stream(uint32_t stream_id)
    {
        std::map<uint32_t, stream_state *>::iterator it = streams.find(stream_id);
        if(it != streams.end()) return it->second;
        stream_state *state = new stream_state();
        state->path = stream_path(stream_id);
        streams[stream_id] = state;
        return state;
    }

    void close_stream(stream_state *state)
    {
        if(state->fd >= 0){
            close(state->fd);
            state->fd = -1;
            if(xmlstream){
                (*xmlstream) << "<byte_run><fileobject><filename>"
                             << state->path
                             << "</filename><filesize>" << state->bytes
                             << "</filesize></fileobject></byte_run>\n";
            }
        }
        state->closed = true;
    }

    void close_all()
    {
        for(std::map<uint32_t, stream_state *>::iterator it=streams.begin();
            it!=streams.end(); ++it){
            stream_state *state = it->second;
            if(!state->closed) close_stream(state);
            if(state->bytes==0) ::unlink(state->path.c_str());
            delete state;
        }
        streams.clear();
        flow::h2_stream_id = 0;
    }

    void write_data(stream_state *state, uint32_t stream_id,
                    const uint8_t *data, size_t length)
    {
        if(length==0) return;
        if(state->fd < 0){
            /* Let filename templates using %H see this HTTP/2 stream id. */
            flow::h2_stream_id = stream_id;
            state->fd = tcpdemux::getInstance()->retrying_open(
                state->path.c_str(),
                O_WRONLY|O_CREAT|O_BINARY|O_TRUNC, 0644);
            flow::h2_stream_id = 0;
            if(state->fd < 0){
                DEBUG(1)("unable to open HTTP/2 stream file %s",
                         state->path.c_str());
                return;
            }
        }
        ssize_t written = write(state->fd, data, length);
        if(written == (ssize_t)length){
            state->bytes += length;
        } else {
            DEBUG(1)("short write to HTTP/2 stream file %s",
                     state->path.c_str());
        }
    }

    void process_frame(uint8_t type, uint8_t flags, uint32_t stream_id,
                       const uint8_t *payload, uint32_t payload_len)
    {
        switch(type){
        case HTTP2_FRAME_DATA:
            if(stream_id==0) return;
            {
                stream_state *state = get_stream(stream_id);
                const uint8_t *data = payload;
                uint32_t data_len = payload_len;
                if(flags & HTTP2_FLAG_PADDED){
                    if(data_len < 1) return;
                    uint8_t pad = data[0];
                    data += 1;
                    data_len -= 1;
                    if(pad >= data_len) return;
                    data_len -= pad;
                }
                write_data(state, stream_id, data, data_len);
                if(flags & HTTP2_FLAG_END_STREAM) close_stream(state);
            }
            break;
        case HTTP2_FRAME_HEADERS:
            if(stream_id==0) return;
            if(flags & HTTP2_FLAG_END_STREAM){
                close_stream(get_stream(stream_id));
            }
            break;
        case HTTP2_FRAME_RST_STREAM:
            if(stream_id!=0 && streams.count(stream_id)){
                close_stream(streams[stream_id]);
            }
            break;
        case HTTP2_FRAME_GOAWAY:
            /* GOAWAY is always on stream 0; streams are flushed at close. */
            break;
        case HTTP2_FRAME_SETTINGS:
        case HTTP2_FRAME_PING:
        case HTTP2_FRAME_WINDOW_UPDATE:
        case HTTP2_FRAME_PRIORITY:
        case HTTP2_FRAME_PUSH_PROMISE:
        case HTTP2_FRAME_CONTINUATION:
            break;                      // control / bookkeeping frames
        default:
            break;                      // unknown frame types are skipped
        }
    }
};

extern "C"
void scan_http2(const class scanner_params &sp,
                const recursion_control_block &rcb)
{
    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
        std::cerr << "scan_http2 requires sp version "
                  << scanner_params::CURRENT_SP_VERSION
                  << "; got version " << sp.sp_version << "\n";
        exit(1);
    }

    if(sp.phase==scanner_params::PHASE_STARTUP){
        sp.info->name = "http2";
        sp.info->author = "tcpflow";
        sp.info->flags = scanner_info::SCANNER_DISABLED;
        return;
    }

    if(sp.phase==scanner_params::PHASE_SCAN){
        const uint8_t *buf = sp.sbuf.buf;
        size_t len = sp.sbuf.bufsize;
        if(!http2_scanner::looks_like_http2(buf, len)) return;

        /* The sbuf forensic path carries the sbuf delimiter suffix;
         * strip it so the derived filenames stay valid on disk. */
        std::string flow_path = sp.sbuf.pos0.path;
        const std::string &delim = sbuf_t::map_file_delimiter;
        if(flow_path.size() >= delim.size() &&
           flow_path.compare(flow_path.size()-delim.size(),
                             delim.size(), delim)==0){
            flow_path.erase(flow_path.size()-delim.size());
        }

        http2_scanner scanner(flow_path, sp.sxml);
        scanner.parse(buf, len);
    }
}
