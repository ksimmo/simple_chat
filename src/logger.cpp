#include <chrono>
#include <iomanip>
#include "logger.h"

Logger* Logger::instance_pointer = nullptr;
std::mutex Logger::mutex;

Logger::Logger(LogLevel level, const std::string& logfile, bool log_to_console, bool append)
{
    this->min_level = level;
    this->current_level = LogLevel::INFO;
    this->log_to_console = log_to_console;
    
    if(!logfile.empty())
    {
        if(append)
            this->log_file_stream.open(logfile, std::ios::out | std::ios::app);
        else
            this->log_file_stream.open(logfile, std::ios::out);
        this->log_to_file = this->log_file_stream.is_open();
    }
}

Logger::~Logger()
{
    if(this->log_to_file && this->log_file_stream.is_open())
        this->log_file_stream.close();
}

Logger& Logger::instance(LogLevel level, const std::string& logfile, bool log_to_console, bool append)
{
    //std::lock_guard<std::mutex> lock(mutex);
    if(instance_pointer==nullptr)
        instance_pointer = new Logger(level, logfile, log_to_console, append);
    //static std::once_flag initFlag;
    //std::call_once(initFlag, [&]() {
    //        instance_pointer = new Logger(level, logfile, log_to_console);
    //    });
    return *instance_pointer;
}

std::string Logger::level_to_string(LogLevel level)
{
    switch (level)
    {
    case LogLevel::DEBUG: return "DEBUG";
    case LogLevel::INFO: return "INFO";
    case LogLevel::WARNING: return "WARNING";
    case LogLevel::ERROR: return "ERROR";
    default: return "UNKOWN";
    }
}

std::string Logger::getTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto timePoint = std::chrono::system_clock::to_time_t(now);
    std::tm* timeInfo = std::localtime(&timePoint);
    
    std::stringstream timestamp;
    timestamp << std::put_time(timeInfo, "%Y-%m-%d %H:%M:%S");
    
    return timestamp.str();
}

void Logger::output_log(const std::string& message)
{
    std::stringstream ss;
    ss << this->getTimestamp() << "[" << this->level_to_string(this->current_level) << "]: " << message;
    if(this->log_to_file)
        this->log_file_stream << ss.str() << std::endl;
    if(this->log_to_console)
        std::cout << ss.str() << std::endl;
}


Logger& Logger::operator<<(LogLevel level)
{
    this->current_level = level;
    return *this;
}

void Logger::flush()
{
    this->output_log(this->log_stream.str()); //ok write or print log
    this->log_stream.str("");
    this->log_stream.clear();
}

/*
Logger& Logger::operator<<(std::ostream& (*manip)(std::ostream&))
{
    if(manip==std::endl)
        this->flush();
}
*/

Logger& Logger::operator<<(const LogEnd& end)
{
    this->flush();
    return *this;
}