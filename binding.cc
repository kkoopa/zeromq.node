/*
 * Copyright (c) 2011 Justin Tulloss
 * Copyright (c) 2010 Justin Tulloss
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <v8.h>
#include <node.h>
#include <node_version.h>
#include <node_buffer.h>
#include <node_internals.h>
#include <zmq.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdexcept>
#include <set>

#ifdef _WIN32
# define snprintf _snprintf_s
  typedef BOOL (WINAPI* SetDllDirectoryFunc)(wchar_t *lpPathName);
  class SetDllDirectoryCaller {
   public:
    explicit SetDllDirectoryCaller() : func_(NULL) { }
    ~SetDllDirectoryCaller() {
      if (func_)
        func_(NULL);
    }
    // Sets the SetDllDirectory function pointer to activates this object.
    void set_func(SetDllDirectoryFunc func) { func_ = func; }
   private:
    SetDllDirectoryFunc func_;
  };
#endif

#define ZMQ_CAN_DISCONNECT (ZMQ_VERSION_MAJOR == 3 && ZMQ_VERSION_MINOR >= 2) || ZMQ_VERSION_MAJOR > 3

using namespace v8;
using namespace node;

enum {
    STATE_READY
  , STATE_BUSY
  , STATE_CLOSED
};

namespace zmq {

  std::set<int> opts_int;
  std::set<int> opts_uint32;
  std::set<int> opts_int64;
  std::set<int> opts_uint64;
  std::set<int> opts_binary;

  class Socket;

  class Context : ObjectWrap {
    friend class Socket;
    public:
      static void Initialize(v8::Handle<v8::Object> target);
      virtual ~Context();

    private:
      Context(int io_threads);
      template<class T> static void New(const v8::FunctionCallbackInfo<T>& info);
      template<class T> static Context *GetContext(const v8::FunctionCallbackInfo<T> &info);

      void Close();
      template<class T> static void Close(const v8::FunctionCallbackInfo<T>& info);

      void* context_;
  };

  class Socket : ObjectWrap {
    public:
      static void Initialize(v8::Handle<v8::Object> target);
      virtual ~Socket();
      void CallbackIfReady();

    private:
      template<class T> static void New(const v8::FunctionCallbackInfo<T> &info);
      Socket(Context *context, int type);
      template<class T> static Socket * GetSocket(const v8::FunctionCallbackInfo<T> &info);

      static void GetState(Local<String> p, const v8::PropertyCallbackInfo<Value>& info);

      template<typename T>
      Handle<Value> GetSockOpt(int option);
      template<typename T>
      Handle<Value> SetSockOpt(int option, Handle<Value> wrappedValue);
      template<class T> static void GetSockOpt(const v8::FunctionCallbackInfo<T> &info);
      template<class T> static void SetSockOpt(const v8::FunctionCallbackInfo<T> &info);

      struct BindState;
      template<class T> static void Bind(const v8::FunctionCallbackInfo<T> &info);

      static void UV_BindAsync(uv_work_t* req);
      static void UV_BindAsyncAfter(uv_work_t* req);

      template<class T> static void BindSync(const v8::FunctionCallbackInfo<T> &info);

      template<class T> static void Connect(const v8::FunctionCallbackInfo<T> &info);
      
#if ZMQ_CAN_DISCONNECT
      template<class T> static void Disconnect(const v8::FunctionCallbackInfo<T> &info);
#endif

      class IncomingMessage;
      template<class T> static void Recv(const v8::FunctionCallbackInfo<T> &info);

      class OutgoingMessage;
      template<class T> static void Send(const v8::FunctionCallbackInfo<T> &info);

      void Close();
      template<class T> static void Close(const v8::FunctionCallbackInfo<T> &info);

      Persistent<Object> context_;
      void *socket_;
      uint8_t state_;
      int32_t endpoints;

      bool IsReady();
      uv_poll_t *poll_handle_;
      static void UV_PollCallback(uv_poll_t* handle, int status, int events);
  };

  Cached<String> callback_symbol;

  static void
  Initialize(Handle<Object> target);

  /*
   * Helpers for dealing with ØMQ errors.
   */

  static inline const char*
  ErrorMessage() {
    return zmq_strerror(zmq_errno());
  }

  static inline Local<Value>
  ExceptionFromError() {
    return Exception::Error(String::New(ErrorMessage()));
  }

  /*
   * Context methods.
   */

  void
  Context::Initialize(v8::Handle<v8::Object> exports) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    Local<FunctionTemplate> t = FunctionTemplate::New(New);
    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "close", Close);

    exports->Set(String::NewSymbol("Context"), t->GetFunction());
  }


  Context::~Context() {
    Close();
  }

  template<class T> void
  Context::New(const v8::FunctionCallbackInfo<T>& info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    assert(info.IsConstructCall());

    int io_threads = 1;
    if (info.Length() == 1) {
      if (!info[0]->IsNumber()) {
        info.GetReturnValue().Set(ThrowException(Exception::TypeError(
          String::New("io_threads must be an integer"))));
        return;
      }
      io_threads = (int) info[0]->ToInteger()->Value();
      if (io_threads < 1) {
        info.GetReturnValue().Set(ThrowException(Exception::RangeError(
          String::New("io_threads must be a positive number"))));
        return;
      }
    }

    Context *context = new Context(io_threads);
    context->Wrap(info.This());

    info.GetReturnValue().Set(info.This());
  }

  Context::Context(int io_threads) : ObjectWrap() {
    context_ = zmq_init(io_threads);
    if (!context_) throw std::runtime_error(ErrorMessage());
  }

  template<class T>
  Context *
  Context::GetContext(const v8::FunctionCallbackInfo<T> &info) {
    return (Context *) *info.This();
  }


  void
  Context::Close() {
    if (context_ != NULL) {
      if (zmq_term(context_) < 0) throw std::runtime_error(ErrorMessage());
      context_ = NULL;
    }
  }

  template<class T> void
  Context::Close(const v8::FunctionCallbackInfo<T>& info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    GetContext(info)->Close();
    info.GetReturnValue().SetUndefined();
  }

  /*
   * Socket methods.
   */

  void
  Socket::Initialize(v8::Handle<v8::Object> exports) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    Local<FunctionTemplate> t = FunctionTemplate::New(New);
    t->InstanceTemplate()->SetInternalFieldCount(1);
    t->InstanceTemplate()->SetAccessor(
        String::NewSymbol("state"), Socket::GetState);

    NODE_SET_PROTOTYPE_METHOD(t, "bind", Bind);
    NODE_SET_PROTOTYPE_METHOD(t, "bindSync", BindSync);
    NODE_SET_PROTOTYPE_METHOD(t, "connect", Connect);
    NODE_SET_PROTOTYPE_METHOD(t, "getsockopt", GetSockOpt);
    NODE_SET_PROTOTYPE_METHOD(t, "setsockopt", SetSockOpt);
    NODE_SET_PROTOTYPE_METHOD(t, "recv", Recv);
    NODE_SET_PROTOTYPE_METHOD(t, "send", Send);
    NODE_SET_PROTOTYPE_METHOD(t, "close", Close);

#if ZMQ_CAN_DISCONNECT
    NODE_SET_PROTOTYPE_METHOD(t, "disconnect", Disconnect);
#endif

    exports->Set(String::NewSymbol("Socket"), t->GetFunction());
    callback_symbol = String::NewSymbol("onReady");
  }

  Socket::~Socket() {
    Close();
  }

  template<class T> void
  Socket::New(const v8::FunctionCallbackInfo<T> &info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    assert(info.IsConstructCall());

    if (info.Length() != 2) {
      info.GetReturnValue().Set(ThrowException(Exception::Error(
          String::New("Must pass a context and a type to constructor"))));
      return;
    }
    assert(info[0]->ToObject()->InternalFieldCount() > 0);
    Context *context = ObjectWrap::Unwrap<Context>(info[0]->ToObject());
    if (!info[1]->IsNumber()) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
          String::New("Type must be an integer"))));
      return;
    }
    int type = (int) info[1]->ToInteger()->Value();

    Socket *socket = new Socket(context, type);
    socket->Wrap(info.This());

    info.GetReturnValue().Set(info.This());
  }

  bool
  Socket::IsReady() {
    zmq_pollitem_t item = {socket_, 0, ZMQ_POLLIN, 0};
    int rc = zmq_poll(&item, 1, 0);
    if (rc < 0) {
      throw std::runtime_error(ErrorMessage());
    }
    return item.revents & ZMQ_POLLIN;
  }

  void
  Socket::CallbackIfReady() {
    if (this->IsReady()) {
      Isolate *isolate = Isolate::GetCurrent();
      HandleScope scope(isolate);

      Local<Value> callback_v = handle()->Get(callback_symbol);
      if (!callback_v->IsFunction()) {
        return;
      }

      TryCatch try_catch;

      callback_v.As<Function>()->Call(handle(), 0, NULL);

      if (try_catch.HasCaught()) {
        FatalException(try_catch);
      }
    }
  }

  void
  Socket::UV_PollCallback(uv_poll_t* handle, int status, int events) {
    assert(status == 0);

    Socket* s = static_cast<Socket*>(handle->data);
    s->CallbackIfReady();
  }

  Socket::Socket(Context *context, int type) : ObjectWrap() {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    context_.Reset(isolate, context->handle());
    socket_ = zmq_socket(context->context_, type);
    state_ = STATE_READY;

    endpoints = 0;

    poll_handle_ = new uv_poll_t;

    poll_handle_->data = this;

    uv_os_sock_t socket;
    size_t len = sizeof(uv_os_sock_t);

    if (zmq_getsockopt(socket_, ZMQ_FD, &socket, &len)) {
      throw std::runtime_error(ErrorMessage());
    }

    uv_poll_init_socket(uv_default_loop(), poll_handle_, socket);
    uv_poll_start(poll_handle_, UV_READABLE, Socket::UV_PollCallback);
  }

  template<class T> Socket *
  Socket::GetSocket(const v8::FunctionCallbackInfo<T> &info) {
    assert(info.This()->InternalFieldCount() > 0);
    return ObjectWrap::Unwrap<Socket>(info.This());
  }

  /*
   * This macro makes a call to GetSocket and checks the socket state. These two
   * things go hand in hand everywhere in our code.
   */
  #define GET_SOCKET(info)                                                 \
      Socket *socket = GetSocket(info);                                    \
      if (socket->state_ == STATE_CLOSED) {                                \
          (info).GetReturnValue().Set(ThrowException(Exception::TypeError( \
              String::New("Socket is closed"))));                          \
          return;                                                          \
      }                                                                    \
      if (socket->state_ == STATE_BUSY) {                                  \
          (info).GetReturnValue().Set(ThrowException(Exception::TypeError( \
              String::New("Socket is busy"))));                            \
          return;                                                          \
      }

  void
  Socket::GetState(Local<String> p, const v8::PropertyCallbackInfo<Value>& info) {
    assert(info.Holder()->InternalFieldCount() > 0);
    Socket* socket = ObjectWrap::Unwrap<Socket>(info.Holder());
    info.GetReturnValue().Set(Integer::New(socket->state_));
  }

  template<typename T>
  Handle<Value> Socket::GetSockOpt(int option) {
    T value = 0;
    size_t len = sizeof(T);
    if (zmq_getsockopt(socket_, option, &value, &len) < 0)
      return ThrowException(ExceptionFromError());
    return Integer::New(value);
  }

  template<typename T>
  Handle<Value> Socket::SetSockOpt(int option, Handle<Value> wrappedValue) {
    if (!wrappedValue->IsNumber())
      return ThrowException(Exception::TypeError(
        String::New("Value must be an integer")));
    T value = (T) wrappedValue->ToInteger()->Value();
    if (zmq_setsockopt(socket_, option, &value, sizeof(T)) < 0)
      return ThrowException(ExceptionFromError());
    return Undefined();
  }

  template<> Handle<Value>
  Socket::GetSockOpt<char*>(int option) {
    char value[1024];
    size_t len = sizeof(value) - 1;
    if (zmq_getsockopt(socket_, option, value, &len) < 0)
      return ThrowException(ExceptionFromError());
    value[len] = '\0';
    return v8::String::New(value);
  }

  template<> Handle<Value>
  Socket::SetSockOpt<char*>(int option, Handle<Value> wrappedValue) {
    if (!Buffer::HasInstance(wrappedValue))
      return ThrowException(Exception::TypeError(
          String::New("Value must be a buffer")));
    Local<Object> buf = wrappedValue->ToObject();
    size_t length = Buffer::Length(buf);
    if (zmq_setsockopt(socket_, option, Buffer::Data(buf), length) < 0)
      return ThrowException(ExceptionFromError());
    return Undefined();
  }

  template<class T>
  void Socket::GetSockOpt(const v8::FunctionCallbackInfo<T> &info) {
    if (info.Length() != 1) {
      info.GetReturnValue().Set(ThrowException(Exception::Error(
          String::New("Must pass an option"))));
      return;
    }
    if (!info[0]->IsNumber()) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
          String::New("Option must be an integer"))));
      return;
    }
    int64_t option = info[0]->ToInteger()->Value();

    GET_SOCKET(info);

    if (opts_int.count(option)) {
      info.GetReturnValue().Set(socket->GetSockOpt<int>(option));
    } else if (opts_uint32.count(option)) {
      info.GetReturnValue().Set(socket->GetSockOpt<uint32_t>(option));
    } else if (opts_int64.count(option)) {
      info.GetReturnValue().Set(socket->GetSockOpt<int64_t>(option));
    } else if (opts_uint64.count(option)) {
      info.GetReturnValue().Set(socket->GetSockOpt<uint64_t>(option));
    } else if (opts_binary.count(option)) {
      info.GetReturnValue().Set(socket->GetSockOpt<char*>(option));
    } else {
      info.GetReturnValue().Set(ThrowException(Exception::Error(
        String::New(zmq_strerror(EINVAL)))));
    }
  }

  template<class T> void Socket::SetSockOpt(const v8::FunctionCallbackInfo<T> &info) {
    if (info.Length() != 2) {
      info.GetReturnValue().Set(ThrowException(Exception::Error(
        String::New("Must pass an option and a value"))));
      return;
    }
    if (!info[0]->IsNumber()) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
          String::New("Option must be an integer"))));
      return;
    }
    int64_t option = info[0]->ToInteger()->Value();

    GET_SOCKET(info);

    if (opts_int.count(option)) {
      info.GetReturnValue().Set(socket->SetSockOpt<int>(option, info[1]));
    } else if (opts_uint32.count(option)) {
      info.GetReturnValue().Set(socket->SetSockOpt<uint32_t>(option, info[1]));
    } else if (opts_int64.count(option)) {
      info.GetReturnValue().Set(socket->SetSockOpt<int64_t>(option, info[1]));
    } else if (opts_uint64.count(option)) {
      info.GetReturnValue().Set(socket->SetSockOpt<uint64_t>(option, info[1]));
    } else if (opts_binary.count(option)) {
      info.GetReturnValue().Set(socket->SetSockOpt<char*>(option, info[1]));
    } else {
      info.GetReturnValue().Set(ThrowException(Exception::Error(
        String::New(zmq_strerror(EINVAL)))));
    }
  }

  struct Socket::BindState {
    BindState(Socket* sock_, Handle<Function> cb_, Handle<String> addr_)
          : addr(addr_) {
      Isolate *isolate = Isolate::GetCurrent();
      HandleScope scope(isolate);
      sock_obj.Reset(isolate, sock_->handle());
      sock = sock_->socket_;
      cb.Reset(isolate, cb_);
      error = 0;
    }

    ~BindState() {
      sock_obj.Dispose();
      sock_obj.Clear();
      cb.Dispose();
      cb.Clear();
    }

    Persistent<Object> sock_obj;
    void* sock;
    Persistent<Function> cb;
    String::Utf8Value addr;
    int error;
  };

  template<class T> void
  Socket::Bind(const v8::FunctionCallbackInfo<T> &info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    if (!info[0]->IsString()) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
          String::New("Address must be a string!"))));
      return;
    }
    Local<String> addr = info[0]->ToString();
    if (info.Length() > 1 && !info[1]->IsFunction()) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
        String::New("Provided callback must be a function"))));
      return;
    }
    Local<Function> cb = Local<Function>::Cast(info[1]);

    GET_SOCKET(info);

    BindState* state = new BindState(socket, cb, addr);
    uv_work_t* req = new uv_work_t;
    req->data = state;
    uv_queue_work(uv_default_loop(),
                  req,
                  UV_BindAsync,
                  (uv_after_work_cb)UV_BindAsyncAfter);
    socket->state_ = STATE_BUSY;

    info.GetReturnValue().SetUndefined();
  }

  void Socket::UV_BindAsync(uv_work_t* req) {
    BindState* state = static_cast<BindState*>(req->data);
    if (zmq_bind(state->sock, *state->addr) < 0)
        state->error = zmq_errno();
  }

  void Socket::UV_BindAsyncAfter(uv_work_t* req) {
    BindState* state = static_cast<BindState*>(req->data);
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    Local<Value> argv[1];

    if (state->error) {
      argv[0] = Exception::Error(String::New(zmq_strerror(state->error)));
    } else {
      argv[0] = Local<Value>::New(Undefined());
    }

    Local<Function> cb = Local<Function>::New(isolate, state->cb);

    assert(Local<Object>::New(isolate, state->sock_obj)->InternalFieldCount() > 0);
    Socket *socket = ObjectWrap::Unwrap<Socket>(Local<Object>::New(isolate, state->sock_obj));
    socket->state_ = STATE_READY;
    delete state;

    if (socket->endpoints == 0) {
      socket->Ref();
    }

    socket->endpoints += 1;

    TryCatch try_catch;
    cb->Call(v8::Context::GetCurrent()->Global(), 1, argv);
    if (try_catch.HasCaught()) {
      FatalException(try_catch);
    }

    delete req;
  }

  template<class T> void
  Socket::BindSync(const v8::FunctionCallbackInfo<T> &info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    if (!info[0]->IsString()) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
        String::New("Address must be a string!"))));
      return;
    }
    String::Utf8Value addr(info[0]->ToString());

    GET_SOCKET(info);

    socket->state_ = STATE_BUSY;

    if (zmq_bind(socket->socket_, *addr) < 0) {
      info.GetReturnValue().Set(ThrowException(ExceptionFromError()));
      return;
    }

    socket->state_ = STATE_READY;

    if (socket->endpoints == 0) {
      socket->Ref();
    }

    socket->endpoints += 1;

    info.GetReturnValue().SetUndefined();
  }

  template<class T> void
  Socket::Connect(const v8::FunctionCallbackInfo<T> &info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    if (!info[0]->IsString()) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
        String::New("Address must be a string!"))));
      return;
    }

    GET_SOCKET(info);

    String::Utf8Value address(info[0]->ToString());
    if (zmq_connect(socket->socket_, *address)) {
      info.GetReturnValue().Set(ThrowException(ExceptionFromError()));
      return;
    }

    if (socket->endpoints == 0) {
      socket->Ref();
    }

    socket->endpoints += 1;

    info.GetReturnValue().SetUndefined();
  }
  
#if ZMQ_CAN_DISCONNECT
  template<class T> void
  Socket::Disconnect(const v8::FunctionCallbackInfo<T> &info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    if (!info[0]->IsString()) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
        String::New("Address must be a string!"))));
      return;
    }

    GET_SOCKET(info);

    String::Utf8Value address(info[0]->ToString());
    if (zmq_disconnect(socket->socket_, *address)) {
      info.GetReturnValue().Set(ThrowException(ExceptionFromError()));
      return;
    }

    socket->endpoints -= 1;
    if (socket->endpoints == 0) {
      socket->Unref();
    }

    info.GetReturnValue().SetUndefined();
  }
#endif

  /*
   * An object that creates an empty ØMQ message, which can be used for
   * zmq_recv. After the receive call, a Buffer object wrapping the ØMQ
   * message can be requested. The reference for the ØMQ message will
   * remain while the data is in use by the Buffer.
   */

  class Socket::IncomingMessage {
    public:
      inline IncomingMessage() {
        msgref_ = new MessageReference();
      };

      inline ~IncomingMessage() {
        if (buf_.IsEmpty() && msgref_) {
          delete msgref_;
          msgref_ = NULL;
        } else {
          buf_.Dispose();
          buf_.Clear();
        }
      };

      inline operator zmq_msg_t*() {
        return *msgref_;
      }

      inline Local<Value> GetBuffer() {
        Isolate *isolate = Isolate::GetCurrent();
        if (buf_.IsEmpty()) {
            Local<Object> buf_obj = Buffer::New(
            (char*)zmq_msg_data(*msgref_), zmq_msg_size(*msgref_),
            FreeCallback, msgref_);
            if (buf_obj.IsEmpty()) {
              return Local<Value>();
            }
            buf_.Reset(isolate, buf_obj);
        }
        return Local<Object>::New(isolate, buf_);
      }

    private:
      static void FreeCallback(char* data, void* message) {
        delete (MessageReference*) message;
      }

      class MessageReference {
        public:
          inline MessageReference() {
            if (zmq_msg_init(&msg_) < 0)
              throw std::runtime_error(ErrorMessage());
          }

          inline ~MessageReference() {
            if (zmq_msg_close(&msg_) < 0)
              throw std::runtime_error(ErrorMessage());
          }

          inline operator zmq_msg_t*() {
            return &msg_;
          }

        private:
          zmq_msg_t msg_;
      };

      Persistent<Object> buf_;
      MessageReference* msgref_;
  };

  template<class T> void Socket::Recv(const v8::FunctionCallbackInfo<T> &info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    int flags = 0;
    int argc = info.Length();
    if (argc == 1) {
      if (!info[0]->IsNumber()) {
        info.GetReturnValue().Set(ThrowException(Exception::TypeError(
          String::New("Argument should be an integer"))));
        return;
      }
      flags = info[0]->ToInteger()->Value();
    }
    else if (argc != 0) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
        String::New("Only one argument at most was expected"))));
    }

    GET_SOCKET(info);

    IncomingMessage msg;
    #if ZMQ_VERSION_MAJOR == 2
      if (zmq_recv(socket->socket_, msg, flags) < 0) {
        info.GetReturnValue().Set(ThrowException(ExceptionFromError()));
        return;
      }
    #else
      if (zmq_recvmsg(socket->socket_, msg, flags) < 0) {
        info.GetReturnValue().Set(ThrowException(ExceptionFromError()));
        return;
      }
    #endif
    info.GetReturnValue().Set(msg.GetBuffer());
  }

  /*
   * An object that creates a ØMQ message from the given Buffer Object,
   * and manages the reference to it using RAII. A persistent V8 handle
   * for the Buffer object will remain while its data is in use by ØMQ.
   */

  class Socket::OutgoingMessage {
    public:
      inline OutgoingMessage(Handle<Object> buf) {
        bufref_ = new BufferReference(buf);
        if (zmq_msg_init_data(&msg_, Buffer::Data(buf), Buffer::Length(buf),
            BufferReference::FreeCallback, bufref_) < 0) {
          delete bufref_;
          throw std::runtime_error(ErrorMessage());
        }
      };

      inline ~OutgoingMessage() {
        if (zmq_msg_close(&msg_) < 0)
          throw std::runtime_error(ErrorMessage());
      };

      inline operator zmq_msg_t*() {
        return &msg_;
      }

    private:
      class BufferReference {
        public:
          inline BufferReference(Handle<Object> buf) {
            Isolate *isolate = Isolate::GetCurrent();
            // Keep the handle alive until zmq is done with the buffer
            noLongerNeeded_ = false;
            buf_.Reset(isolate, buf);
            buf_.MakeWeak(isolate, this, &WeakCheck);
          }

          inline ~BufferReference() {
            buf_.Dispose();
            buf_.Clear();
          }

          // Called by zmq when the message has been sent.
          // NOTE: May be called from a worker thread. Do not modify V8/Node.
          static void FreeCallback(void* data, void* message) {
            // Raise a flag indicating that we're done with the buffer
            ((BufferReference*)message)->noLongerNeeded_ = true;
          }

          // Called when V8 would like to GC buf_
          static void WeakCheck(Isolate* isolate, Persistent<Object>* obj, BufferReference* data) {
            if ((data)->noLongerNeeded_) {
              delete data;
            } else {
              // Still in use, revive, prevent GC
              obj->MakeWeak(isolate, data, &WeakCheck);
            }
          }

        private:
          bool noLongerNeeded_;
          Persistent<Object> buf_;
      };

    zmq_msg_t msg_;
    BufferReference* bufref_;
  };

  // WARNING: the buffer passed here will be kept alive
  // until zmq_send completes, possibly on another thread.
  // Do not modify or reuse any buffer passed to send.
  // This is bad, but allows us to send without copying.
  template<class T> void Socket::Send(const v8::FunctionCallbackInfo<T> &info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    int argc = info.Length();
    if (argc != 1 && argc != 2) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
        String::New("Must pass a Buffer and optionally flags"))));
      return;
    }
    if (!Buffer::HasInstance(info[0])) {
      info.GetReturnValue().Set(ThrowException(Exception::TypeError(
        String::New("First argument should be a Buffer"))));
      return;
    }
    int flags = 0;
    if (argc == 2) {
      if (!info[1]->IsNumber()) {
        info.GetReturnValue().Set(ThrowException(Exception::TypeError(
          String::New("Second argument should be an integer"))));
        return;
      }
      flags = info[1]->ToInteger()->Value();
    }

    GET_SOCKET(info);

#if 0  // zero-copy version, but doesn't properly pin buffer and so has GC issues
    OutgoingMessage msg(info[0]->ToObject());
    if (zmq_send(socket->socket_, msg, flags) < 0) {
        info.GetReturnValue().Set(ThrowException(ExceptionFromError()));
        return;
    }

#else // copying version that has no GC issues
    zmq_msg_t msg;
    Local<Object> buf = info[0]->ToObject();
    size_t len = Buffer::Length(buf);
    int res = zmq_msg_init_size(&msg, len);
    if (res != 0) {
      info.GetReturnValue().Set(ThrowException(ExceptionFromError()));
      return;
    }

    char * cp = (char *)zmq_msg_data(&msg);
    const char * dat = Buffer::Data(buf);
    std::copy(dat, dat + len, cp);

    #if ZMQ_VERSION_MAJOR == 2
      if (zmq_send(socket->socket_, &msg, flags) < 0) {
        info.GetReturnValue().Set(ThrowException(ExceptionFromError()));
        return;
      }
    #else
      if (zmq_sendmsg(socket->socket_, &msg, flags) < 0) {
        info.GetReturnValue().Set(ThrowException(ExceptionFromError()));
        return;
      }
    #endif
#endif // zero copy / copying version

    info.GetReturnValue().SetUndefined();
  }


  void
  Socket::Close() {
    if (socket_) {
      if (zmq_close(socket_) < 0)
        throw std::runtime_error(ErrorMessage());
      socket_ = NULL;
      state_ = STATE_CLOSED;
      context_.Dispose();
      context_.Clear();
      
      if (this->endpoints > 0)
        this->Unref();
      this->endpoints = 0;

      uv_poll_stop(poll_handle_);
    }
  }

  template<class T> void
  Socket::Close(const v8::FunctionCallbackInfo<T> &info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    GET_SOCKET(info);
    socket->Close();
    info.GetReturnValue().SetUndefined();
  }

  // Make zeromq versions less than 2.1.3 work by defining
  // the new constants if they don't already exist
  #if (ZMQ_VERSION < 20103)
  #   define ZMQ_DEALER ZMQ_XREQ
  #   define ZMQ_ROUTER ZMQ_XREP
  #endif

  /*
   * Module functions.
   */

  template<class T> static void
  ZmqVersion(const v8::FunctionCallbackInfo<T>& info) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    int major, minor, patch;
    zmq_version(&major, &minor, &patch);

    char version_info[16];
    snprintf(version_info, 16, "%d.%d.%d", major, minor, patch);

    info.GetReturnValue().Set(String::New(version_info));
  }

  static void
  Initialize(Handle<Object> target) {
    Isolate *isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    opts_int.insert(14); // ZMQ_FD
    opts_int.insert(16); // ZMQ_TYPE
    opts_int.insert(17); // ZMQ_LINGER
    opts_int.insert(18); // ZMQ_RECONNECT_IVL
    opts_int.insert(19); // ZMQ_BACKLOG
    opts_int.insert(21); // ZMQ_RECONNECT_IVL_MAX
    opts_int.insert(23); // ZMQ_SNDHWM
    opts_int.insert(24); // ZMQ_RCVHWM
    opts_int.insert(25); // ZMQ_MULTICAST_HOPS
    opts_int.insert(27); // ZMQ_RCVTIMEO
    opts_int.insert(28); // ZMQ_SNDTIMEO
    opts_int.insert(29); // ZMQ_RCVLABEL
    opts_int.insert(30); // ZMQ_RCVCMD
    opts_int.insert(31); // ZMQ_IPV4ONLY
    opts_int.insert(33); // ZMQ_ROUTER_MANDATORY
    opts_int.insert(34); // ZMQ_TCP_KEEPALIVE
    opts_int.insert(35); // ZMQ_TCP_KEEPALIVE_CNT
    opts_int.insert(36); // ZMQ_TCP_KEEPALIVE_IDLE
    opts_int.insert(37); // ZMQ_TCP_KEEPALIVE_INTVL
    opts_int.insert(39); // ZMQ_DELAY_ATTACH_ON_CONNECT
    opts_int.insert(40); // ZMQ_XPUB_VERBOSE
    opts_int.insert(41); // ZMQ_ROUTER_RAW
    opts_int.insert(42); // ZMQ_IPV6

    opts_int64.insert(3); // ZMQ_SWAP
    opts_int64.insert(8); // ZMQ_RATE
    opts_int64.insert(10); // ZMQ_MCAST_LOOP
    opts_int64.insert(20); // ZMQ_RECOVERY_IVL_MSEC
    opts_int64.insert(22); // ZMQ_MAXMSGSIZE

    opts_uint64.insert(1); // ZMQ_HWM
    opts_uint64.insert(4); // ZMQ_AFFINITY

    opts_binary.insert(5); // ZMQ_IDENTITY
    opts_binary.insert(6); // ZMQ_SUBSCRIBE
    opts_binary.insert(7); // ZMQ_UNSUBSCRIBE
    opts_binary.insert(32); // ZMQ_LAST_ENDPOINT
    opts_binary.insert(38); // ZMQ_TCP_ACCEPT_FILTER

    // transition types
    #if ZMQ_VERSION_MAJOR >= 3
    opts_int.insert(15); // ZMQ_EVENTS 3.x int
    opts_int.insert(8); // ZMQ_RATE 3.x int
    opts_int.insert(9); // ZMQ_RECOVERY_IVL 3.x int
    opts_int.insert(13); // ZMQ_RCVMORE 3.x int
    opts_int.insert(11); // ZMQ_SNDBUF 3.x int
    opts_int.insert(12); // ZMQ_RCVBUF 3.x int
    #else
    opts_uint32.insert(15); // ZMQ_EVENTS 2.x uint32_t
    opts_int64.insert(8); // ZMQ_RATE 2.x int64_t
    opts_int64.insert(9); // ZMQ_RECOVERY_IVL 2.x int64_t
    opts_int64.insert(13); // ZMQ_RCVMORE 2.x int64_t
    opts_uint64.insert(11); // ZMQ_SNDBUF 2.x uint64_t
    opts_uint64.insert(12); // ZMQ_RCVBUF 2.x uint64_t
    #endif

    NODE_DEFINE_CONSTANT(target, ZMQ_CAN_DISCONNECT);
    NODE_DEFINE_CONSTANT(target, ZMQ_PUB);
    NODE_DEFINE_CONSTANT(target, ZMQ_SUB);
    #if ZMQ_VERSION_MAJOR == 3
    NODE_DEFINE_CONSTANT(target, ZMQ_XPUB);
    NODE_DEFINE_CONSTANT(target, ZMQ_XSUB);
    #endif
    NODE_DEFINE_CONSTANT(target, ZMQ_REQ);
    NODE_DEFINE_CONSTANT(target, ZMQ_XREQ);
    NODE_DEFINE_CONSTANT(target, ZMQ_REP);
    NODE_DEFINE_CONSTANT(target, ZMQ_XREP);
    NODE_DEFINE_CONSTANT(target, ZMQ_DEALER);
    NODE_DEFINE_CONSTANT(target, ZMQ_ROUTER);
    NODE_DEFINE_CONSTANT(target, ZMQ_PUSH);
    NODE_DEFINE_CONSTANT(target, ZMQ_PULL);
    NODE_DEFINE_CONSTANT(target, ZMQ_PAIR);

    NODE_DEFINE_CONSTANT(target, ZMQ_POLLIN);
    NODE_DEFINE_CONSTANT(target, ZMQ_POLLOUT);
    NODE_DEFINE_CONSTANT(target, ZMQ_POLLERR);

    NODE_DEFINE_CONSTANT(target, ZMQ_SNDMORE);
    #if ZMQ_VERSION_MAJOR == 2
    NODE_DEFINE_CONSTANT(target, ZMQ_NOBLOCK);
    #endif

    NODE_DEFINE_CONSTANT(target, STATE_READY);
    NODE_DEFINE_CONSTANT(target, STATE_BUSY);
    NODE_DEFINE_CONSTANT(target, STATE_CLOSED);

    NODE_SET_METHOD(target, "zmqVersion", ZmqVersion);

    Context::Initialize(target);
    Socket::Initialize(target);
  }
} // namespace zmq


// module

extern "C" void
init(Handle<Object> target) {
#ifdef _MSC_VER
  // On Windows, inject the windows/lib folder into the DLL search path so that
  // it will pick up our bundled DLL in case we do not have zmq installed on
  // this system.
  HMODULE kernel32_dll = GetModuleHandleW(L"kernel32.dll");
  SetDllDirectoryCaller caller;
  SetDllDirectoryFunc set_dll_directory;
  wchar_t path[MAX_PATH] = L"";
  wchar_t pathDir[MAX_PATH] = L"";
  if (kernel32_dll != NULL) {
    set_dll_directory =
          (SetDllDirectoryFunc)GetProcAddress(kernel32_dll, "SetDllDirectoryW");
    if (set_dll_directory) {
      GetModuleFileNameW(GetModuleHandleW(L"zmq.node"), path, MAX_PATH - 1);
      wcsncpy(pathDir, path, wcsrchr(path, '\\') - path);
      path[0] = '\0';
      pathDir[wcslen(pathDir)] = '\0';
# ifdef _WIN64
      wcscat(pathDir, L"\\..\\..\\windows\\lib\\x64");
# else
      wcscat(pathDir, L"\\..\\..\\windows\\lib\\x86");
# endif
      _wfullpath(path, pathDir, MAX_PATH);
      set_dll_directory(path);
      caller.set_func(set_dll_directory);
      LoadLibrary("libzmq-v100-mt-3_2_2");
    }
  }
#endif
  zmq::Initialize(target);
}

NODE_MODULE(zmq, init)
