#include <nan.h>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "crypto/equihash.h"


#include <vector>
using namespace v8;

const char* ToCString(const String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

int verifyEH(const char *hdr, const std::vector<unsigned char> &soln, unsigned int n, unsigned int k, const char *pers){
  // Hash state
  crypto_generichash_blake2b_state state;
  EhInitialiseState(n, k, state, pers);

  crypto_generichash_blake2b_update(&state, (const unsigned char*)hdr, 140);

  bool isValid;
  if (n == 200 && k == 9) {
      isValid = Eh200_9.IsValidSolution(state, soln);
  } else if (n == 192 && k == 7) {
      isValid = Eh192_7.IsValidSolution(state, soln);
  } else if (n == 144 && k == 5) {
      isValid = Eh144_5.IsValidSolution(state, soln);
  } else if (n == 96 && k == 5) {
      isValid = Eh96_5.IsValidSolution(state, soln);
  } else if (n == 96 && k == 3) {
      isValid = Eh96_3.IsValidSolution(state, soln);
  } else if (n == 48 && k == 5) {
      isValid = Eh48_5.IsValidSolution(state, soln);
  } else {
      throw std::invalid_argument("Unsupported Equihash parameters");
  }
  
  return isValid;
}

void Verify(const v8::FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  if (args.Length() < 4) {
  isolate->ThrowException(Exception::TypeError(
    String::NewFromUtf8(isolate, "Wrong number of arguments")));
  return;
  }

  if (!args[2]->IsInt32() || !args[3]->IsInt32()) {
  isolate->ThrowException(Exception::TypeError(
    String::NewFromUtf8(isolate, "Invalid equihash parameters (n, k)")));
  return;
  }

//  if (!args[4]->IsString()) {
//  isolate->ThrowException(Exception::TypeError(
//    String::NewFromUtf8(isolate, "Invalid equihash personalization strings (pers)")));
//  return;
//  }

  Local<Object> header = args[0]->ToObject();
  Local<Object> solution = args[1]->ToObject();

  if(!node::Buffer::HasInstance(header) || !node::Buffer::HasInstance(solution)) {
  isolate->ThrowException(Exception::TypeError(
    String::NewFromUtf8(isolate, "Arguments should be buffer objects.")));
  return;
  }

  const char *hdr = node::Buffer::Data(header);
  if(node::Buffer::Length(header) != 140) {
	  //invalid hdr length
	  args.GetReturnValue().Set(false);
	  return;
  }
  const char *soln = node::Buffer::Data(solution);

  std::vector<unsigned char> vecSolution(soln, soln + node::Buffer::Length(solution));

  // equihash parameters n, k, pers
  unsigned int n = args[2]->Uint32Value();
  unsigned int k = args[3]->Uint32Value();
  String::Utf8Value str(args[4]);
  const char* pers = ToCString(str);

  //printf("equihashverify.cc: n=%d, k=%d, pers=%s\n", n, k, pers);
  bool result = verifyEH(hdr, vecSolution, n, k, pers);
  args.GetReturnValue().Set(result);
}

void Init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "verify", Verify);
}

NODE_MODULE(equihashverify, Init)
