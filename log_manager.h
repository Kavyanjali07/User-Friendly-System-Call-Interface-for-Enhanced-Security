#ifndef LOG_MANAGER_H
#define LOG_MANAGER_H

#include <string>

void logEvent(const std::string& eventType, const std::string& details);
void displayLogs();

#endif
