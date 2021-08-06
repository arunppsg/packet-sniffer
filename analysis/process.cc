#include <string>
#include <iostream>
#include <vector>
#include <fstream>

#include "xxhash.h"
#include "dirent.h"
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/writer.h"

using namespace rapidjson;

std::vector <std::string> get_json_files_in_dir(){
    std::vector <std::string> output_files;
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir ("/home/arun/iitm/ps-i/ps-mmap/analysis/logs")) != NULL) {
        while ((ent = readdir (dir)) != NULL) {
            std::string file_name = ent->d_name;
            if(file_name.substr(0, 6) == "output" &&
                    file_name.substr(file_name.length() - 5, file_name.length()) == ".json"){
                output_files.push_back(("logs/"+file_name));
            }
        }
        closedir (dir);
    } else {
      /* could not open directory */
        perror ("");
    }
    return output_files;
}

std::vector <std::string> parse_json(std::string){
    std::vector <std::string> s;
    return s;
}

int main() {
    std::vector <std::string> output_jsons = get_json_files_in_dir();
/*    std::cout << "Log files are ";
    for(int i=0; i<output_jsons.size(); i++);
       std::cout << output_jsons[i] << " ";*/

    std::string line;
    std::ifstream infile(output_jsons[0]);
    int count = 0;
    while(std::getline(infile, line) && count < 100){
      //  std::cout << line << std::endl;
        count++;
    }

    const char *json = line.c_str();
    Document document;
    document.Parse(json);

    assert(document.IsObject());

    Value &_hash = document["payload_hash"]; 
    StringBuffer sb;
    Writer<StringBuffer> writer(sb);
    _hash.Accept(writer);
    std::string s = sb.GetString();
    printf("PAyload hash is %s \n", s.c_str());
//    printf("Payloas hash is %s \n", document["payload_hash"].GetString()); */
    
    /*FILE *fp = fopen(output_jsons[0].c_str(), "r");

    char readBuffer[65536];
    FileReadStream is(fp, readBuffer, sizeof(readBuffer));

    Document d;
    d.ParseStream(is);

    fclose(fp);*/
    return 0;
}
