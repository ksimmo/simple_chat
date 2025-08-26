#include <fstream>

#include "logger.h"
#include "config.h"

Config* Config::instance_pointer = nullptr;

Config::Config(const nlohmann::json& defaults, const std::string& config_file) : data(defaults)
{
    Logger& logger = Logger::instance();
    //load file
    if(!config_file.empty())
    {
        std::ifstream file(config_file);
        if(file.is_open())
        {
            try 
            {
                nlohmann::json file_data;
                file >> file_data;

                //ok overwrite defaults
                for (auto& [key, value] : file_data.items()) 
                    this->data[key] = value;
            }
            catch(const std::exception& e) 
            {
                logger << LogLevel::ERROR << "JSON parsing error: " << e.what() << LogEnd();
            }
        }
        else
            logger << LogLevel::ERROR << "Cannot open config file: " << config_file << LogEnd();
    }
}

Config::~Config()
{
}

Config& Config::instance(const nlohmann::json& defaults, const std::string& config_file)
{
    if(instance_pointer==nullptr)
        instance_pointer = new Config(defaults, config_file);

    return *instance_pointer;
}