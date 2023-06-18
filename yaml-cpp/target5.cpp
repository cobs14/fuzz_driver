#include <fstream>
#include "yaml-cpp/yaml.h"
#include <iostream>
#include <string>
#include <cstdio>
#include <assert.h>

using namespace std;



void test_node_api(string s) {
  YAML::Node node;
  assert(node.IsNull());
  if (s.length()>2){
    node["elem1"]=s[1];
    assert(node.IsMap());
    for (int i = 0; i< s.length() && i < 10; i++){
        node["seq"].push_back(s[i]);
    }
    assert(node["seq"].IsSequence());
    node.remove(s[0]);  
    }
}

void parse(std::istream& input) {
  try {
    YAML::Node doc = YAML::Load(input);
  } catch (const YAML::Exception& e) {
  }
}

void test_parse_api(string s)
{
    std::istringstream is(s);
    parse(is);
}

void test_emitter_api(string s){
    YAML::Emitter out;
    out << s;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    std::string s((const char*)Data, Size);
    test_emitter_api(s);
    test_parse_api(s);
    test_node_api(s);
	return 0;
}

