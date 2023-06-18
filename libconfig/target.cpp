#include <fstream>
#include <libconfig.h++>
#include <iostream>
#include <string>
#include <cstdio>
#include <assert.h>
#include <libconfig.h>

using namespace std;
using namespace libconfig;


void test_c_api(string s)
{
    config_t cfg;
    config_setting_t *root, *setting, *movie;

    config_init(&cfg);
    config_set_options(&cfg,
                     (CONFIG_OPTION_FSYNC
                      | CONFIG_OPTION_SEMICOLON_SEPARATORS
                      | CONFIG_OPTION_COLON_ASSIGNMENT_FOR_GROUPS
                      | CONFIG_OPTION_OPEN_BRACE_ON_SEPARATE_LINE));

    if(! config_read_string(&cfg, s.c_str()))
    {
        config_destroy(&cfg);
        return;
    }
    root = config_root_setting(&cfg);
    
    setting = config_setting_get_member(root, "inventory");
    if(!setting)
        setting = config_setting_add(root, "inventory", CONFIG_TYPE_GROUP);
    
    setting = config_setting_get_member(setting, "movies");
    if(!setting)
        setting = config_setting_add(setting, "movies", CONFIG_TYPE_LIST);
    
    movie = config_setting_add(setting, NULL, CONFIG_TYPE_GROUP);

    setting = config_setting_add(movie, "title", CONFIG_TYPE_STRING);

    setting = config_setting_add(movie, "media", CONFIG_TYPE_STRING);
    
    setting = config_lookup(&cfg, "inventory.moives");

    config_destroy(&cfg);        

}

void test_cpp_api(string s){
    Config cfg;
    cfg.setOptions(Config::OptionFsync
                | Config::OptionSemicolonSeparators
                | Config::OptionColonAssignmentForGroups
                | Config::OptionOpenBraceOnSeparateLine);
    try
    { 
        cfg.readString("example.cfg");
    }
    catch(const FileIOException &fioex)
    {
        std::cerr << "I/O error while reading file." << std::endl;
        return;
    }
    catch(const ParseException &pex)
    {
        std::cerr << "Parse error at " << pex.getFile() << ":" << pex.getLine()
                << " - " << pex.getError() << std::endl;
        return;
    }
    Setting &root = cfg.getRoot();

    if(! root.exists("inventory"))
        root.add("inventory", Setting::TypeGroup);

    Setting &inventory = root["inventory"];

    if(! inventory.exists("movies"))
        inventory.add("movies", Setting::TypeList);

    Setting &movies = inventory["movies"];

    // Create the new movie entry.
    Setting &movie = movies.add(Setting::TypeGroup);

    movie.add("title", Setting::TypeString) = s.c_str();
    movie.add("media", Setting::TypeString) = s.c_str();

    try
    {
        Setting &con = cfg.lookup("inventory.movies");
    }
    catch(const SettingNotFoundException &nfex)
    {
        cerr << "No 'movies' setting in configuration file." << endl;
    }

}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    std::string s((const char*)Data, Size);
    // test config read.
    test_c_api(s);
    test_cpp_api(s);
    return 0;
}

