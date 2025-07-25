#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <thread>
#include "db/database.h"
#include "logger.h"

Database::Database()
{
}

Database::~Database()
{
    this->disconnect();
}

bool Database::connect(const std::string& name, int flags)
{
    int status = sqlite3_open_v2(name.c_str(), &this->db, flags, NULL);
    if(status!=SQLITE_OK)
    {
        Logger& logger = Logger::instance();
        logger << LogLevel::ERROR << "Could not open database " << name << ": " << sqlite3_errmsg(this->db) << " (" << status << ")!" << LogEnd();
        return false;
    }

    return true;
}

void Database::disconnect()
{
    sqlite3_close(this->db);

    this->column_names.clear();
    for(auto i=0;i<this->values.size();i++)
    {
        for(auto j=0;j<this->values[i].size();j++)
            delete this->values[i][j];
    }
    this->values.clear();
}

bool Database::run_query(const std::string& query, const char* fmt, ...)
{
    Logger& logger = Logger::instance();
    //clear data from last query
    this->column_names.clear();
    for(auto i=0;i<this->values.size();i++)
    {
        for(auto j=0;j<this->values[i].size();j++)
            delete this->values[i][j];
    }
    this->values.clear();

    //create statement
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(this->db, query.c_str(), query.length()+1, &stmt, nullptr);
    if(result!=SQLITE_OK)
    {
        logger << LogLevel::ERROR << "Could not prepare query: " << sqlite3_errmsg(this->db) << " (" << result << ")!" << LogEnd();
        return false;
    }

    int num_columns = sqlite3_column_count(stmt);
    int num_binds = sqlite3_bind_parameter_count(stmt);

    for(int i=0;i<num_columns;i++)
    {
        //std::cout << "Name: " << sqlite3_column_name(stmt,i) << " Type: " << sqlite3_column_type(stmt,i) << std::endl;
        std::string name = const_cast<const char*>(sqlite3_column_name(stmt,i));
        this->column_names.push_back(name);
    }

    bool status = true;

    //ok if we insert values use bind here
    if(fmt!=nullptr && num_binds>0)
    {
        va_list args;
        va_start(args, fmt);
        int index = 1; //leftmost has index of 1

        //TODO: support multi row bind! using vectors, indicate with v at beginning
        while(*fmt!='\0')
        {
            switch (*fmt)
            {
            case 'i': //integer
            {
                int i = va_arg(args, int);
                if(sqlite3_bind_int(stmt, index, i)!=SQLITE_OK)
                {
                    logger << LogLevel::ERROR << "Could not bind int: " << sqlite3_errmsg(this->db) << " (" << result << ")!" << LogEnd();
                    status = false;
                }
                break;
            }
            case 'f': //float
            case 'd': //double
            {
                double d = va_arg(args, double);
                if(sqlite3_bind_double(stmt, index, d)!=SQLITE_OK)
                {
                    logger << LogLevel::ERROR << "Could not bind double: " << sqlite3_errmsg(this->db) << " (" << result << ")!" << LogEnd();
                    status = false;
                }
                break;
            }
            case 's': //string
            {
                const char* c = va_arg(args, const char*);
                if(sqlite3_bind_text(stmt, index, c, -1, SQLITE_STATIC)!=SQLITE_OK)
                {
                    logger << LogLevel::ERROR << "Could not bind text: " << sqlite3_errmsg(this->db) << " (" << result << ")!" << LogEnd();
                    status = false;
                }
                break;
            }
            case 'b': //blob
            {
                int length = va_arg(args, int);
                void* p = va_arg(args, void*);
                if(sqlite3_bind_blob(stmt, index, p, length, SQLITE_STATIC)!=SQLITE_OK)
                {
                    logger << LogLevel::ERROR << "Could not bind blob: " << sqlite3_errmsg(this->db) << " (" << result << ")!" << LogEnd();
                    status = false;
                }
                break;
            }
            case 't': //time
            {
                std::chrono::system_clock::time_point* p = (std::chrono::system_clock::time_point*)va_arg(args, void*);
                
                std::chrono::system_clock::time_point tp = *p;
                std::time_t time = std::chrono::system_clock::to_time_t(tp);
                std::tm tm = *std::gmtime(&time); //we use GMT (alterantive UTC)

                auto duration = tp.time_since_epoch();
                auto fractional_seconds = duration - std::chrono::duration_cast<std::chrono::seconds>(duration);
                auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(fractional_seconds).count();

                std::stringstream ss;
                ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
                ss << "." << std::setw(3) << std::setfill('0') << microseconds/1000;

                if(sqlite3_bind_text(stmt, index, ss.str().c_str(), -1, SQLITE_STATIC)!=SQLITE_OK)
                {
                    logger << LogLevel::ERROR << "Could not bind date: " << sqlite3_errmsg(this->db) << " (" << result << ")!" << LogEnd();
                    status = false;
                }

                break;
            }
            }
            ++fmt;
            if(!status)
                break;
            index++;
        }
        va_end(args);
    }

    if(!status)
    {
        sqlite3_finalize(stmt);
        return false;
    }

    //step through data
    int num_tries = 0; //how often a step fails due to SQL_BUSY
    while(true)
    {
        result = sqlite3_step(stmt);
        if(result==SQLITE_DONE)
            break;
        else if(result==SQLITE_ROW)
        {
            std::vector<DBEntry*> temp;
            temp.reserve(num_columns);
            //we have data -> loop over columns
            for(int i=0;i<num_columns;i++)
            {
                DBEntry* entry;
                int dtype = sqlite3_column_type(stmt, i);
                switch(dtype)
                {
                case SQLITE_INTEGER:
                {
                    int a = sqlite3_column_int(stmt, i);
                    entry = new DBEntry(dtype, &a);
                    break;
                }
                case SQLITE_FLOAT:
                {
                    double d = sqlite3_column_double(stmt, i);
                    entry = new DBEntry(dtype, &d);
                    break;
                } 
                case SQLITE_TEXT:
                {
                    int size = sqlite3_column_bytes(stmt, i);
                    const unsigned char* s = sqlite3_column_text(stmt, i);
                    entry = new DBEntry(dtype, s, size);
                    break;
                }
                case SQLITE_BLOB:
                {
                    int size = sqlite3_column_bytes(stmt, i);
                    const void* blob = sqlite3_column_blob(stmt, i);
                    entry = new DBEntry(dtype, blob, size);
                    break;
                }
                default:
                {
                    //empty element
                    entry = new DBEntry(SQLITE_NULL, nullptr);
                    break;
                }  
                }   
                temp.push_back(entry);
            }
            this->values.push_back(temp);
        }
        else if(result==SQLITE_BUSY)
        {
            if(num_tries>5) //TODO: make this configurable
                break;
            else
            {
                //sleep and retry again?
                num_tries += 1;
                std::this_thread::sleep_for(std::chrono::milliseconds(100)); //sleep for 100ms
            }
        }
        else
        {
            logger << LogLevel::ERROR << "[-]Query step error: " << sqlite3_errmsg(this->db) << " (" << result << ")!" << LogEnd();
            status = false;
            break;
        }
            
    }

    if(num_tries>5) //TODO: see above
        return false;
    
    //finalize
    sqlite3_finalize(stmt);

    return true;
}

bool Database::exists_table(const std::string& name)
{
    std::string query = "SELECT name FROM sqlite_master WHERE type='table' AND name='" + name + "';";
    bool status = this->run_query(query, nullptr);
    
    if(status)
        //check returned data for sucess
        status = this->values.size()>0; //if table exists, we get a row

    return status;
}