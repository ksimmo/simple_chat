#ifndef CONFIG_H
#define CONFIG_H

#include <iostream>
#include <string>

#include "json/single_include/nlohmann/json.hpp"

class Config
{
private:
    static Config* instance_pointer;
    nlohmann::json data; //the configuration data

    Config(const nlohmann::json& defaults, const std::string& config_file); //prevent unwanted creation //TODO: add defaults here

public:
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    ~Config();

    static Config& instance(const nlohmann::json& defaults={}, const std::string& config_file="");

    //TODO: add getter
    template<typename T> T get(const std::string& key)
    {
        return data.at(key).get<T>();
    }  
};

#endif