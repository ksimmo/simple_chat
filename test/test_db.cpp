#include <iostream>
#include <chrono>
#include <iomanip>

#include "db/database.h"

std::string time_to_str(std::chrono::system_clock::time_point tp)
{
    std::time_t time = std::chrono::system_clock::to_time_t(tp);
    std::tm tm = *std::localtime(&time);

    auto duration = tp.time_since_epoch();
    auto fractional_seconds = duration - std::chrono::duration_cast<std::chrono::seconds>(duration);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(fractional_seconds).count();

    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setw(3) << std::setfill('0') << microseconds/1000;
    return ss.str();
}

int main(int argc, char* argv[])
{
    Database db = Database();
    db.connect("test.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    
    std::vector<std::vector<DBEntry>> results;
    db.run_query("DROP TABLE dates;", results, nullptr);
    db.run_query("CREATE TABLE IF NOT EXISTS dates (date TEXT NOT NULL);", results, nullptr);

    std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
    //db.run_query("INSERT INTO dates (date) VALUES(?);", "s", 4, "test");
    db.run_query("INSERT INTO dates (date) VALUES(?);", results, "t", &tp);
    db.run_query("INSERT INTO dates (date) VALUES(?);", results, "s", 23, "2025-01-01 08:20:00.000");

    std::string s = time_to_str(tp);
    db.run_query("INSERT INTO dates (date) VALUES(?);", results, "s", s.length(), s.c_str());

    db.run_query("SELECT * FROM dates;", results, nullptr);
    for(int i=0;i<results.size();i++)
    {
        std::string s;
        results[i][0].get_string(s);
        std::cout << i << ": " << s << " " << s.length() << std::endl;
    }

    std::chrono::system_clock::time_point ttp;
    results[0][0].get_time(ttp);
    db.run_query("DELETE FROM dates WHERE date=?;", results, "t", &ttp);
    std::cout << "deleted! " << db.num_affected_rows() << std::endl;

    std::cout << "Equal? " << (tp==ttp) << " | " << time_to_str(tp) << " " << time_to_str(ttp) << " | " << (time_to_str(tp)==time_to_str(ttp)) << std::endl;

    db.run_query("DELETE FROM dates WHERE date=?;", results, "s", 23, "2025-01-01 08:20:00.000");
    std::cout << "deleted! " << db.num_affected_rows() << std::endl;


    /////////////////////////
    std::vector<unsigned char> v = {'t', 'e', 's', 't'};
    db.run_query("DROP TABLE blobs;", results, nullptr);
    db.run_query("CREATE TABLE IF NOT EXISTS blobs (id INTEGER, data BLOB NOT NULL);", results, nullptr);
    db.run_query("INSERT INTO blobs (id,data) VALUES(?,?);", results, "ib", 128, v.size(), v.data());

    db.run_query("SELECT * FROM blobs;", results, nullptr);
    std::vector<unsigned char> v2 = results[0][1].get_buffer();
    std::cout << "vector equal: " << (v==v2) << std::endl;
    db.run_query("DELETE FROM blobs WHERE id=? AND data=?;", results, "ib", 128, v2.size(), v2.data());
    std::cout << "deleted! " << db.num_affected_rows() << std::endl;


    return 0;
}