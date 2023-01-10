#include "FileHandleFinder.h"


int main()
{  
	FileHandleFinder dCrack;
	int ID = 0;
	std::vector<std::string> paths;
	// if process is found
	if (dCrack.FindProcessIDByName("Discord", ID)) {
		if (dCrack.findProcessFileHandles(ID, paths) == 0) {
			for (auto& p : paths) {
				std::cout << p << '\n';
			}
			std::cout << '\n';
			std::cout << "DONE!";
		}
	}
    return 0;
}