#include <iostream>
#include "db/database.h"

Database::Database()
{
}

Database::~Database()
{
    sqlite3_close(this->db);
}

bool Database::connect(std::string name, int flags)
{
    int status = sqlite3_open_v2(name.c_str(), &this->db, flags, NULL);
    if(status!=SQLITE_OK)
    {
        std::cerr << "Could not open database " << name << ": " << sqlite3_errmsg(this->db) << " (" << status << ")!" << std::endl;
        return false;
    }

    return true;
}

void Database::disconnect()
{
    sqlite3_close(this->db);
}

int Database::callback(void* unused, int argc, char** argv, char** col_name)
{
    return 0;
}

bool Database::run_query(std::string query)
{
    //clear data from last query
    this->column_names.clear();
    this->column_datatypes.clear();
    this->values.clear();

    //create statement
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(this->db, query.c_str(), query.length()+1, &stmt, nullptr);
    if(result!=SQLITE_OK)
    {
        std::cerr << "Could not prepare query: " << sqlite3_errmsg(this->db) << " (" << result << ")!" << std::endl;
        return false;
    }

    int num_columns = sqlite3_column_count(stmt);

    //step through data
    bool status = true;
    bool first_time = true;
    while(true)
    {
        result = sqlite3_step(stmt);
        if(result==SQLITE_DONE)
            break;
        else if(result==SQLITE_ROW)
        {
            std::vector<std::string> temp;
            temp.reserve(num_columns);
            //we have data -> loop over columns
            for(int i=0;i<num_columns;i++)
            {
                if(first_time)
                {
                    std::string name = const_cast<const char*>(sqlite3_column_name(stmt,i));
                    this->column_names.push_back(name);

                    this->column_datatypes.push_back(sqlite3_column_type(stmt,i));
                }
                
                std::string text = const_cast<const char*>(sqlite3_column_name(stmt,i));
                temp.push_back(text);

            }
            first_time = false;
            this->values.push_back(temp);
        }
        else if(result==SQLITE_BUSY)
        {
            //sleep and retry again?
        }
        else
        {
            std::cerr << "[-]Query step error: " << sqlite3_errmsg(this->db) << " (" << result << ")!" << std::endl;
            status = false;
            break;
        }
            
    }
    
    //finalize
    sqlite3_finalize(stmt);

    return true;
}

bool Database::exists_table(std::string name)
{
    std::string query = "SELECT name FROM sqlite_master WHERE type='table' AND name='" + name + "';";
    bool status = this->run_query(query);
    
    if(status)
        //check returned data for sucess
        status = this->values.size()>0; //if table exists, we get a row

    return status;
}