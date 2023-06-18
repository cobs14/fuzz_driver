#include <fstream>
#include <expat.h>
#include <iostream>
#include <string>
#include <cstdio>
#include <assert.h>
#include <string.h>


using namespace std;

#ifdef XML_LARGE_SIZE
#  define XML_FMT_INT_MOD "ll"
#else
#  define XML_FMT_INT_MOD "l"
#endif

#ifdef XML_UNICODE_WCHAR_T
#  define XML_FMT_STR "ls"
#else
#  define XML_FMT_STR "s"
#endif

static void XMLCALL
startElement(void *userData, const XML_Char *name, const XML_Char **atts) {
    int i;
    int *const depthPtr = (int *)userData;
    (void)atts;

    for (i = 0; i < *depthPtr; i++)
        putchar('\t');
    printf("%" XML_FMT_STR "\n", name);
    *depthPtr += 1;
}

static void XMLCALL
endElement(void *userData, const XML_Char *name) {
    int *const depthPtr = (int *)userData;
    (void)name;

    *depthPtr -= 1;
}
void test_parse(const uint8_t *data, size_t size)
{
    XML_Parser p = XML_ParserCreate(NULL);

    XML_SetElementHandler(p, startElement, endElement);
    XML_Parse(p, (const XML_Char *)data, size, 0);
    XML_Parse(p, (const XML_Char *)data, size, 1);
    XML_ParserFree(p);
          // fprintf(stderr, "test 4\n");
}

void test_parsebuf(const uint8_t *data, size_t size)
{
    
    XML_Parser p = XML_ParserCreate(NULL);

    XML_SetElementHandler(p, startElement, endElement);

    void *buf = XML_GetBuffer(p, size);
    // assert(buf);

    memcpy(buf, data, size);
    XML_ParseBuffer(p, size, size == 0);
    XML_ParserFree(p);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size == 0) return 0;

    test_parse(Data,Size);
    test_parsebuf(Data,Size);
    XML_Parser parser = XML_ParserCreate(NULL);
    int done;
    int depth = 0;
// fprintf(stderr, "test 1\n");
    XML_SetUserData(parser, &depth);
    XML_SetElementHandler(parser, startElement, endElement);
    // fprintf(stderr, "test 2\n");

    void *const buf = XML_GetBuffer(parser, BUFSIZ);
    if (! buf) {
      // fprintf(stderr, "Couldn't allocate memory for buffer\n");
      XML_ParserFree(parser);
      return 0;
    }

    // const size_t len = fread(buf, 1, BUFSIZ, stdin);
    memcpy(buf, Data, Size);
        // fprintf(stderr, "test 3\n");
    if (XML_ParseBuffer(parser, (int)Size, true) == XML_STATUS_ERROR) {
        // fprintf(stderr,
        //         "Parse error at line %" XML_FMT_INT_MOD "u:\n%" XML_FMT_STR "\n",
        //         XML_GetCurrentLineNumber(parser),
        //         XML_ErrorString(XML_GetErrorCode(parser)));
        XML_ParserFree(parser);
        return 0;
    }
          fprintf(stderr, "test 3\n");

  XML_ParserFree(parser);
  return 0;
}

