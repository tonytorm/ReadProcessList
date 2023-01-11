#include "FileHandleFinder.h"
#include <iostream>
#include <filesystem>
#include <chrono>


double calculateLastModificationTime(std::string path);



int main()
{  
	FileHandleFinder dCrack;
	int ID = 0;
	std::vector<std::string> paths;
	// if process is found
	if (dCrack.FindProcessIDByName("Discord", ID)) {
		if (dCrack.findProcessFileHandles(ID, paths) == 0) {
			for (auto& p : paths) {
				std::cout << p << calculateLastModificationTime(p) << '\n';
				
			}
			std::cout << '\n';
			std::cout << "DONE!";
		}
	}
    return 0;
}




double calculateLastModificationTime(std::string path) {
	std::filesystem::path file_path = path;
	try {
		std::filesystem::file_time_type ft = std::filesystem::last_write_time(file_path);
		auto time_point = std::chrono::time_point_cast<std::chrono::seconds>(ft);
		auto ns = time_point.time_since_epoch().count();
		
		std::cout << "Modification time in seconds: " << ns << std::endl;
		return ns;
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cout << e.what() << '\n';
	}
	return 0;
}