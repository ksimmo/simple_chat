#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <atomic>
#include <mutex>
#include <memory>

enum LogLevel {DEBUG, INFO, WARNING, ERROR};

class Logger
{
private:
    static Logger* instance_pointer;
    static std::mutex mutex;

    bool log_to_console;
    bool log_to_file;

    std::ofstream log_file_stream;

    LogLevel min_level;
    LogLevel current_level;

    Logger(LogLevel level, const std::string& logfile, bool log_to_console); //prevent unwanted creation

    std::string level_to_string(LogLevel level);
    std::string getTimestamp();
    void output_log(const std::string& message);
public:
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    ~Logger();

    static Logger& instance(LogLevel level=LogLevel::INFO, const std::string& logfile="", bool log_to_console=true);

    void setLogLevel(LogLevel new_level) {this->min_level = new_level; }

    Logger& operator<<(LogLevel level);
    template< typename T>
    Logger& operator<<(const T& message);
};

template <typename T>
Logger& Logger::operator<<(const T& message)
{
    if(this->current_level>=this->min_level)
    {
        std::lock_guard<std::mutex> lock(this->mutex);
        std::stringstream ss;
        ss << message;

        this->output_log(ss.str());
    }
    return *this;
}

#endif